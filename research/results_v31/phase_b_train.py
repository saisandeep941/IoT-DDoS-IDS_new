"""Train B1/B2 with a fixed 01-12/validation/CIC-IDS2017 split protocol."""
from __future__ import annotations
import csv, hashlib, json, sys, time
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

ROOT=Path(__file__).resolve().parents[2]
R=ROOT/'research'/'results_v31'
sys.path.insert(0,str(ROOT/'model_v3'))
sys.path.insert(0,str(ROOT/'research'/'code'))
from v3_loader import V3Model
from research_eval_protocol import canonical_tuple_keys, parse_timestamp_ns

DAY=Path(r'C:\Users\bonus\Desktop\IoT-DDoS-IDS\dataset\01-12')
CIC=Path(r'C:\Users\bonus\Desktop\CIC-IDS2017-Benchmark\MachineLearningCVE')
MAX_ROWS=1_500_000; PER_GROUP_CAP=3000; CHUNK=250_000; SEED=42
TUPLE_FIELDS=['Source IP','Destination IP','Source Port','Destination Port','Protocol']

def headers(path):
    with path.open('r',encoding='utf-8-sig',newline='') as f: return next(csv.reader(f))

def parse_time(s):
    x=pd.to_datetime(s.astype('string').str.strip(),format='ISO8601',utc=True,errors='coerce')
    return x

def first_pass(paths,features):
    info={}
    for path in paths:
        cols=headers(path); required=['Timestamp','Label']
        raw={c.strip():c for c in cols}
        if any(c not in raw for c in required): raise ValueError(f'{path} missing Timestamp/Label')
        counts=defaultdict(int); lo=None;hi=None;rows=0
        for chunk in pd.read_csv(path,usecols=[raw['Timestamp']],chunksize=CHUNK,low_memory=False):
            chunk.columns=[c.strip() for c in chunk.columns]
            ts=parse_time(chunk['Timestamp']); valid=ts.notna();
            if valid.any(): lo=ts[valid].min() if lo is None else min(lo,ts[valid].min()); hi=ts[valid].max() if hi is None else max(hi,ts[valid].max())
            rows+=len(chunk)
        if lo is None or hi is None: raise ValueError(f'{path.name}: no parseable timestamps')
        cutoff=lo+(hi-lo)*0.8
        # The prior loop's moving cutoff is only for counts; recompute exact eligible groups in pass two.
        info[path]={"min":lo,"max":hi,"cutoff":cutoff,"rows":rows,"counts":dict(counts)}
        print(f'Inspected {path.name}: {rows:,} rows, {lo.isoformat()} .. {hi.isoformat()}',flush=True)
    return info

def exact_group_counts(paths,info):
    groups=defaultdict(int); benign=0
    for path in paths:
        raw={c.strip():c for c in headers(path)}
        for chunk in pd.read_csv(path,usecols=[raw['Timestamp'],raw['Label']],chunksize=CHUNK,low_memory=False):
            chunk.columns=[c.strip() for c in chunk.columns]
            ts=parse_time(chunk['Timestamp']); train=ts.notna() & (ts < info[path]['cutoff']-pd.Timedelta(seconds=60))
            labs=chunk.loc[train,'Label'].astype('string').str.strip(); mins=ts[train].dt.floor('min').astype('string')
            benign_mask=labs.str.upper().eq('BENIGN').fillna(False).to_numpy()
            benign+=int(benign_mask.sum())
            attacks=pd.DataFrame({'label':labs.to_numpy(dtype=str),'minute':mins.to_numpy(dtype=str)})
            attacks=attacks.loc[~benign_mask]
            for (label,minute),count in attacks.groupby(['label','minute'],sort=False).size().items():
                groups[(str(label),str(minute))]+=int(count)
    if benign>=MAX_ROWS: raise RuntimeError(f'All eligible BENIGN rows={benign:,} exceed {MAX_ROWS:,} total-row cap; cannot satisfy both constraints.')
    budget=MAX_ROWS-benign; active={k:min(PER_GROUP_CAP,v) for k,v in groups.items() if v}
    quotas={k:0 for k in active}; remaining=budget
    while remaining and active:
        share=max(1,remaining//len(active)); used=0
        for key in list(active):
            add=min(active[key]-quotas[key],share,remaining-used)
            if add>0: quotas[key]+=add;used+=add
            if quotas[key]>=active[key]: del active[key]
            if used>=remaining: break
        if not used: break
        remaining-=used
    print(f'Eligible benign={benign:,}, attack minute groups={len(groups):,}, attack budget={MAX_ROWS-benign:,}, total sampling cap={MAX_ROWS:,}',flush=True)
    return quotas

def collect_01(paths,features,info,quotas):
    rng=np.random.default_rng(SEED); valtuples=set(); benign_x=[]; benign_keys=[]; reservoirs={}; scanned=0; validation_rows=0
    for path in paths:
        col=headers(path); raw={c.strip():c for c in col}
        wanted=list(dict.fromkeys([*features,'Timestamp','Label',*TUPLE_FIELDS]))
        missing=[c for c in wanted if c not in raw]
        if missing: raise ValueError(f'{path.name} missing fields: {missing}')
        use=[raw[c] for c in wanted]
        for chunk in pd.read_csv(path,usecols=use,chunksize=CHUNK,low_memory=False):
            chunk.columns=[c.strip() for c in chunk.columns]; scanned+=len(chunk)
            ts=parse_time(chunk['Timestamp']); valid=ts.notna(); cut=info[path]['cutoff']
            val=valid & (ts>=cut)
            if val.any():
                keys,_=canonical_tuple_keys(chunk.loc[val,TUPLE_FIELDS]); valtuples.update(str(k) for k in keys)
                validation_rows+=int(val.sum())
            train=valid & (ts<cut-pd.Timedelta(seconds=60))
            if not train.any(): continue
            part=chunk.loc[train]; tuple_keys,tuple_valid=canonical_tuple_keys(part[TUPLE_FIELDS])
            if not tuple_valid.all():
                part=part.loc[tuple_valid]; tuple_keys=tuple_keys[tuple_valid]
                train_times=ts[train].loc[tuple_valid]
            else: train_times=ts[train]
            minute=train_times.dt.floor('min').astype('string').to_numpy()
            labels=part['Label'].astype('string').str.strip().to_numpy()
            x=part[features].apply(pd.to_numeric,errors='coerce').replace([np.inf,-np.inf],np.nan).to_numpy(dtype=np.float32)
            for lab in np.unique(labels):
                mask=labels==lab
                if str(lab).upper()=='BENIGN':
                    benign_x.append(x[mask]);benign_keys.extend(str(k) for k in tuple_keys[mask]);continue
                for mn in np.unique(minute[mask]):
                    group_mask=mask & (minute==mn); key=(str(lab),str(mn)); cap=quotas.get(key,0)
                    if cap<=0: continue
                    gx=x[group_mask]; gk=np.asarray([str(k) for k in tuple_keys[group_mask]],dtype=object)
                    gp=rng.random(len(gx)); old=reservoirs.get(key)
                    if old is not None:
                        ox,ok,op=old; gx=np.concatenate((ox,gx));gk=np.concatenate((ok,gk));gp=np.concatenate((op,gp))
                    if len(gx)>cap:
                        chosen=np.argpartition(gp,-cap)[-cap:];gx=gx[chosen];gk=gk[chosen];gp=gp[chosen]
                    reservoirs[key]=(gx,gk,gp)
        print(f'Sampled {path.name}: scanned {scanned:,} rows; validation rows so far={validation_rows:,}',flush=True)
    attacks=[(x,k) for x,k,_ in reservoirs.values()]
    ax=np.concatenate([v[0] for v in attacks]) if attacks else np.empty((0,len(features)),np.float32)
    ak=np.concatenate([v[1] for v in attacks]) if attacks else np.empty(0,dtype=object)
    bx=np.concatenate(benign_x) if benign_x else np.empty((0,len(features)),np.float32); bk=np.asarray(benign_keys,dtype=object)
    keep_a=np.asarray([k not in valtuples for k in ak]);keep_b=np.asarray([k not in valtuples for k in bk])
    ax=ax[keep_a];bx=bx[keep_b]
    if len(ax)+len(bx)>MAX_ROWS: raise RuntimeError('Post-purge training sample exceeded row cap')
    X=np.concatenate((bx,ax)); y=np.r_[np.zeros(len(bx),dtype=np.int8),np.ones(len(ax),dtype=np.int8)]
    order=np.random.default_rng(SEED).permutation(len(y));X=X[order];y=y[order]
    report={'eligible_validation_rows':validation_rows,'validation_unique_tuple_keys':len(valtuples),'tuple_purged_training_rows':int((~keep_a).sum()+(~keep_b).sum()),'sampled_training_rows':len(y),'sampled_benign':len(bx),'sampled_attack':len(ax),'minute_groups_sampled':len(reservoirs),'attack_per_group_max':max((len(v[0]) for v in reservoirs.values()),default=0),'time_split':'each source file cutoff = min timestamp + 80% of observed duration; train rows earlier than cutoff minus 60 s; validation rows on/after cutoff; all validation 5-tuples purged from training'}
    return X,y,report

def collect_cic(features,per_class=100_000):
    # Deterministic bounded reservoir gives CIC Monday--Thursday diversity without reading full files into RAM.
    files=sorted([p for p in CIC.glob('*.csv') if not p.name.casefold().startswith('friday')],key=lambda p:p.name.casefold())
    if len(files)!=5: raise RuntimeError(f'Expected 5 CIC-IDS2017 Mon-Thu files, found {len(files)}')
    rng=np.random.default_rng(SEED+1); xs={0:np.empty((0,len(features)),np.float32),1:np.empty((0,len(features)),np.float32)}; pri={0:np.empty(0),1:np.empty(0)}; seen=Counter()
    for path in files:
        col=headers(path); raw={c.strip():c for c in col}; miss=[c for c in [*features,'Label'] if c not in raw]
        if miss: raise RuntimeError(f'{path.name} missing V3 features: {miss}')
        for chunk in pd.read_csv(path,usecols=[raw[c] for c in [*features,'Label']],chunksize=CHUNK,low_memory=False):
            chunk.columns=[c.strip() for c in chunk.columns]; labs=chunk['Label'].astype('string').str.strip().str.upper(); labels=np.where(labs.eq('BENIGN'),0,1)
            fx=chunk[features].apply(pd.to_numeric,errors='coerce').replace([np.inf,-np.inf],np.nan).to_numpy(dtype=np.float32)
            for cls in (0,1):
                part=fx[labels==cls]; seen[cls]+=len(part)
                if not len(part): continue
                pp=rng.random(len(part)); newx=np.concatenate((xs[cls],part)); newp=np.concatenate((pri[cls],pp))
                if len(newx)>per_class: keep=np.argpartition(newp,-per_class)[-per_class:];newx=newx[keep];newp=newp[keep]
                xs[cls],pri[cls]=newx,newp
        print(f'Read CIC training file {path.name}',flush=True)
    x=np.concatenate((xs[0],xs[1])); y=np.r_[np.zeros(len(xs[0]),np.int8),np.ones(len(xs[1]),np.int8)]
    return x,y,{'source_files':[str(p) for p in files],'eligible_rows_by_class':{str(k):v for k,v in seen.items()},'reservoir_rows_by_class':{str(k):len(xs[k]) for k in xs},'sampling':'uniform fixed-seed reservoir, max 100000 per binary class across Mon-Thu files'}

def train(name,X,y,model):
    prepared=model.prepare(pd.DataFrame(X,columns=model.features))
    clf=XGBClassifier(n_estimators=150,max_depth=6,learning_rate=.3,subsample=1.0,colsample_bytree=1.0,reg_lambda=1.0,tree_method='hist',n_jobs=4,random_state=SEED,eval_metric='logloss')
    start=time.time();clf.fit(prepared,y);elapsed=time.time()-start
    return clf,elapsed

def main():
    model=V3Model();features=model.features;paths=sorted(DAY.glob('*.csv'),key=lambda p:p.name.casefold())
    if len(paths)!=11: raise RuntimeError(f'Expected 11 source files; found {len(paths)}')
    checkpoint=R/'phase_b_scan_checkpoint.json'
    fingerprints={str(p):{'size':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns} for p in paths}
    cached=None
    if checkpoint.is_file():
        try: cached=json.loads(checkpoint.read_text(encoding='utf-8'))
        except (OSError,ValueError): cached=None
    if cached and cached.get('fingerprints')==fingerprints:
        info={Path(k):{'min':pd.Timestamp(v['min']),'max':pd.Timestamp(v['max']),'cutoff':pd.Timestamp(v['cutoff']),'rows':v['rows'],'counts':{}} for k,v in cached['files'].items()}
        print('Reusing timestamp scan checkpoint; source size/mtime fingerprints match.',flush=True)
    else:
        info=first_pass(paths,features)
        checkpoint.write_text(json.dumps({'fingerprints':fingerprints,'files':{str(p):{'min':v['min'].isoformat(),'max':v['max'].isoformat(),'cutoff':v['cutoff'].isoformat(),'rows':v['rows']} for p,v in info.items()}},indent=2),encoding='utf-8')
    quotas=exact_group_counts(paths,info);X,y,rep=collect_01(paths,features,info,quotas)
    if len(y)==0 or len(np.unique(y))!=2: raise RuntimeError(f'Training sample lacks both classes: {Counter(y.tolist())}')
    model1,t1=train('b1',X,y,model)
    report={'protocol':'B1 trains only CIC-DDoS2019 01-12; per-file time cutoff by 80% of observed duration, 60s purge gap, undirected five-tuple purge; all eligible BENIGN rows; attacks sampled at max 3000 per label/minute, total <=1.5M; fixed XGBoost configuration (150 trees, depth 6, eta .3, seed 42). B2 adds up to 100000 examples per binary class sampled from CIC-IDS2017 Monday-Thursday.','features':features,'b1':{**rep,'training_seconds':t1,'class_counts':dict(Counter(y.tolist()))}}
    with (R/'phase_b_training.npz').open('wb') as f: np.savez_compressed(f,X=X,y=y)
    XX,yy,crep=collect_cic(features)
    X2=np.concatenate((X,XX));y2=np.r_[y,yy];model2,t2=train('b2',X2,y2,model)
    report['b2']={**crep,'training_seconds':t2,'training_rows':len(y2),'class_counts':dict(Counter(y2.tolist()))}
    (R/'phase_b_train_raw.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':main()
