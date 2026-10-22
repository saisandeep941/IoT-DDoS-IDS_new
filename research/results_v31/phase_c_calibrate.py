"""Fit isotonic V3 calibration on first-half 03-11 and evaluate later data."""
from __future__ import annotations
import csv, json, sys, time
from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import brier_score_loss

ROOT=Path(__file__).resolve().parents[2];R=ROOT/'research'/'results_v31'
sys.path.insert(0,str(ROOT/'model_v3'))
from v3_loader import V3Model
UDPLAG=Path(r'C:\Users\bonus\Desktop\CICDDoS2019-03-11-Test\UDPLag.csv')
CIC=Path(r'C:\Users\bonus\Desktop\CIC-IDS2017-Benchmark\MachineLearningCVE')
CHUNK=25000;BOOT=1000;SEED=42;BINS=15

def load_score(paths,model,cic=False):
    yy=[];pp=[];tt=[];labs=[]
    for path in paths:
        with path.open('r',encoding='utf-8-sig',newline='') as f: raw=next(csv.reader(f))
        headers=[x.strip() for x in raw]; ix=[headers.index(x) for x in model.features]; li=headers.index('Label');ti=headers.index('Timestamp') if 'Timestamp' in headers else None
        start=time.time();rows=0
        with path.open('r',encoding='utf-8-sig',newline='') as f:
            reader=csv.reader(f,strict=True);next(reader);batch=[];bl=[];bt=[];br=[]
            for row in reader:
                if len(row)!=len(headers): continue
                lab=row[li].strip();
                if not lab or lab.casefold() in {'nan','null','none','na','n/a'}:continue
                y=int(lab.upper()!='BENIGN')
                if cic and y and 'DDOS' not in lab.upper(): continue
                batch.append(row);bl.append(y);bt.append(row[ti].strip() if ti is not None else None);br.append(lab)
                if len(batch)>=CHUNK:
                    fdf=pd.DataFrame(batch,columns=headers);pp.extend(model.predict_proba_attack(fdf).tolist());yy.extend(bl);tt.extend(bt);labs.extend(br);rows+=len(batch)
                    batch=[];bl=[];bt=[];br=[]
            if batch:
                fdf=pd.DataFrame(batch,columns=headers);pp.extend(model.predict_proba_attack(fdf).tolist());yy.extend(bl);tt.extend(bt);labs.extend(br);rows+=len(batch)
        print(f'Predicted {path.name}: {rows:,} rows ({time.time()-start:.1f}s)',flush=True)
    times=(pd.to_datetime(pd.Series(tt),format='ISO8601',utc=True,errors='coerce')
           if tt and tt[0] is not None else None)
    return np.asarray(yy,dtype=np.int8),np.asarray(pp,dtype=float),times,np.asarray(labs,dtype=object)

def ece(y,p):
    edges=np.linspace(0,1,BINS+1);value=0.;parts=[]
    for i in range(BINS):
        mask=(p>=edges[i]) & ((p<edges[i+1]) if i<BINS-1 else (p<=edges[i+1]))
        if not mask.any(): continue
        obs=float(y[mask].mean());conf=float(p[mask].mean());value+=float(mask.mean())*abs(obs-conf)
        parts.append({'bin':[float(edges[i]),float(edges[i+1])],'rows':int(mask.sum()),'mean_probability':conf,'observed_rate':obs})
    return value,parts

def boot_ci(y,p,cal):
    rng=np.random.default_rng(SEED);c0=np.flatnonzero(y==0);c1=np.flatnonzero(y==1)
    n0,n1=len(c0),len(c1);vals={k:[] for k in ('brier_before','brier_after','ece_before','ece_after')}
    for _ in range(BOOT):
        ix=np.r_[rng.choice(c0,n0,replace=True),rng.choice(c1,n1,replace=True)]
        a=p[ix];b=cal[ix];z=y[ix]
        vals['brier_before'].append(float(brier_score_loss(z,a)));vals['brier_after'].append(float(brier_score_loss(z,b)))
        vals['ece_before'].append(float(ece(z,a)[0]));vals['ece_after'].append(float(ece(z,b)[0]))
    return {k:[float(np.quantile(v,.025)),float(np.quantile(v,.975))] for k,v in vals.items()}

def summarize(name,y,p,cal,labs):
    before,bbins=ece(y,p);after,abins=ece(y,cal)
    return {'dataset':name,'rows':int(len(y)),'class_counts':{'BENIGN':int((y==0).sum()),'ATTACK':int((y==1).sum())},'brier_before':float(brier_score_loss(y,p)),'brier_after':float(brier_score_loss(y,cal)),'ece_before':before,'ece_after':after,'ci95_stratified_bootstrap':boot_ci(y,p,cal),'binning':{'strategy':'15 fixed-width probability bins on [0,1]','before':bbins,'after':abins},'raw_label_counts':dict(Counter(labs.tolist()))}

def main():
    model=V3Model(); y,p,t,labs=load_score([UDPLAG],model)
    good=t.notna().to_numpy(); y=y[good];p=p[good];labs=labs[good];t=t[good].reset_index(drop=True)
    start=t.min();end=t.max();split=start+(end-start)/2;calmask=(t<split).to_numpy();testmask=~calmask
    calibrator=IsotonicRegression(out_of_bounds='clip',y_min=0.,y_max=1.).fit(p[calmask],y[calmask])
    p_cal=calibrator.predict(p[calmask]);p_test=calibrator.predict(p[testmask])
    results=[summarize('CIC-DDoS2019 03-11 UDPLag second half',y[testmask],p[testmask],p_test,labs[testmask])]
    cy,cp,ct,cl=load_score([CIC/'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',CIC/'Friday-WorkingHours-Morning.pcap_ISCX.csv'],model,cic=True)
    cc=calibrator.predict(cp);results.append(summarize('CIC-IDS2017 Friday DDoS + benign morning',cy,cp,cc,cl))
    iso={'x_thresholds':[float(x) for x in calibrator.X_thresholds_],'y_thresholds':[float(x) for x in calibrator.y_thresholds_],'out_of_bounds':'clip','training_rows':int(calmask.sum()),'training_class_counts':{'BENIGN':int((y[calmask]==0).sum()),'ATTACK':int((y[calmask]==1).sum())},'first_half_start_utc':start.isoformat(),'first_half_end_utc':split.isoformat(),'test_half_end_utc':end.isoformat(),'seed':SEED}
    out={'protocol':'Frozen V3 isotonic calibration fit only on first 50% of full 03-11 UDPLag by capture-time midpoint; evaluation on second half and external CIC-IDS2017 Friday DDoS plus benign Friday morning; ECE uses 15 fixed-width bins; bootstrap 1000 stratified replicates drawing each class at its full observed test-set size, seed 42.','calibration':iso,'results':results}
    (R/'phase_c_calibration.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    (R/'isotonic_calibrator.json').write_text(json.dumps({'x_thresholds':iso['x_thresholds'],'y_thresholds':iso['y_thresholds'],'out_of_bounds':'clip'},indent=2),encoding='utf-8')
    print(json.dumps(out,indent=2),flush=True)
if __name__=='__main__':main()
