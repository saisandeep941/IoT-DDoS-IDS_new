"""Chunked, no-retuning evaluation of frozen V3; writes raw JSON results."""
from __future__ import annotations
import csv, json, sys, time
from collections import Counter
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "model_v3"))
from v3_loader import V3Model

R = ROOT / "research" / "results_v31"
DATA = Path(r"C:\Users\bonus\Desktop\IoT-DDoS-IDS\dataset\01-12")
UDPLAG = Path(r"C:\Users\bonus\Desktop\CICDDoS2019-03-11-Test\UDPLag.csv")
CIC = Path(r"C:\Users\bonus\Desktop\CIC-IDS2017-Benchmark\MachineLearningCVE")
POINTS = {"balanced": 0.5, "strict": 0.9988}
BOOTSTRAPS, BOOTSTRAP_CLASS_N = 1000, 2000

def read_header(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        names = [x.strip() for x in next(csv.reader(f, strict=True))]
    counts, used = Counter(), set()
    out=[]
    for name in names:
        idx=counts[name]; candidate=name
        if candidate in used:
            k=max(1,idx)
            while f"{name}.{k}" in used or f"{name}.{k}" in names: k+=1
            candidate=f"{name}.{k}"
        counts[name]+=1; used.add(candidate); out.append(candidate)
    return out

def score_files(paths, model, label_name="Label", cic=False):
    scores=[]; labels=[]; raw_labels=[]; raw_counts=Counter(); names=model.features
    for path in paths:
        header=read_header(path)
        missing=[x for x in [*names,label_name] if x not in header]
        if missing: raise ValueError(f"{path}: missing model fields {missing}")
        indexes=[header.index(x) for x in names]; li=header.index(label_name)
        start=time.time(); rows=0
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader=csv.reader(f, strict=True); next(reader)
            batch=[]; batch_labels=[]
            for row in reader:
                if len(row)!=len(header): continue
                lab=row[li].strip();
                if not lab or lab.casefold() in {"nan","null","none","na","n/a"}: continue
                y=int(lab.upper()!="BENIGN")
                if cic and y and "DDOS" not in lab.upper():
                    continue
                raw_counts[lab]+=1
                batch.append(row)
                batch_labels.append(y)
                if len(batch)>=25000:
                    frame=pd.DataFrame(batch,columns=header)
                    scores.extend(model.predict_proba_attack(frame).tolist()); labels.extend(batch_labels)
                    raw_labels.extend([row[li].strip() for row in batch])
                    rows+=len(batch); batch=[]; batch_labels=[]
            if batch:
                frame=pd.DataFrame(batch,columns=header)
                scores.extend(model.predict_proba_attack(frame).tolist()); labels.extend(batch_labels)
                raw_labels.extend([row[li].strip() for row in batch]); rows+=len(batch)
        print(f"Scored {path.name}: {rows:,} rows in {time.time()-start:.1f}s", flush=True)
    return np.asarray(labels,dtype=np.int8),np.asarray(scores,dtype=np.float64),dict(raw_counts),np.asarray(raw_labels,dtype=object)

def metric(y,p,t):
    pred=p>=t; positives=y==1; negatives=~positives
    tp=int(np.sum(pred&positives)); fp=int(np.sum(pred&negatives)); fn=int(np.sum(~pred&positives)); tn=int(np.sum(~pred&negatives))
    return {"threshold":t,"recall":tp/(tp+fn) if tp+fn else None,"FPR":fp/(fp+tn) if fp+tn else None,"precision":tp/(tp+fp) if tp+fp else 0.0,"tp":tp,"fp":fp,"fn":fn,"tn":tn}

def evaluate(name,y,p,raw,raw_labels):
    if not len(y) or set(np.unique(y))!={0,1}: raise ValueError(f"{name}: require both classes, got {Counter(y.tolist())}")
    rng=np.random.default_rng(42); pos=np.flatnonzero(y==1); neg=np.flatnonzero(y==0)
    n=min(BOOTSTRAP_CLASS_N,len(pos),len(neg)); draws={k:[] for k in ["roc_auc",*[(m,key) for m in POINTS for key in ("recall","FPR","precision")]]}
    for _ in range(BOOTSTRAPS):
        ix=np.r_[rng.choice(neg,n,replace=True),rng.choice(pos,n,replace=True)]
        yy=y[ix]; pp=p[ix]; draws["roc_auc"].append(float(roc_auc_score(yy,pp)))
        for mode,t in POINTS.items():
            mm=metric(yy,pp,t)
            # Bootstrap the class-conditional rates at their full observed
            # denominators, preserving prevalence for precision intervals.
            full=metric(y,p,t)
            tp=rng.binomial(len(pos),full["recall"])
            fp=rng.binomial(len(neg),full["FPR"])
            draws[(mode,"recall")].append(tp/len(pos))
            draws[(mode,"FPR")].append(fp/len(neg))
            draws[(mode,"precision")].append(tp/(tp+fp) if tp+fp else 0.0)
    def ci(values): return [float(np.quantile(values,.025)),float(np.quantile(values,.975))]
    points={}
    for mode,t in POINTS.items():
        m=metric(y,p,t); m["ci95"]={k:ci(draws[(mode,k)]) for k in ("recall","FPR","precision")}; points[mode]=m
    by_label={}
    for lab in sorted(set(raw_labels.tolist())):
        mask=raw_labels==lab
        if lab.upper()=="BENIGN":
            by_label[lab]={"rows":int(mask.sum()),"recall_as_benign_at_thresholds":{mode:float(np.mean(p[mask]<t)) for mode,t in POINTS.items()}}
        else:
            by_label[lab]={"rows":int(mask.sum()),"recall_at_thresholds":{mode:float(np.mean(p[mask]>=t)) for mode,t in POINTS.items()}}
    return {"dataset":name,"rows":int(len(y)),"class_counts":{"BENIGN":int(np.sum(y==0)),"ATTACK":int(np.sum(y==1))},"raw_label_counts":raw,"roc_auc":float(roc_auc_score(y,p)),"roc_auc_ci95":ci(draws["roc_auc"]),"operating_points":points,"per_label_recall":by_label,"bootstrap":{"replicates":BOOTSTRAPS,"stratified_class_sample_size":n,"seed":42}}

def main():
    model=V3Model(); results=[]
    y,p,raw,labels=score_files([UDPLAG],model)
    results.append(evaluate("CIC-DDoS2019 03-11 full UDPLag",y,p,raw,labels))
    # DDoS afternoon attacks plus Friday morning benign rows; PortScan excluded by design.
    files=[CIC/"Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",CIC/"Friday-WorkingHours-Morning.pcap_ISCX.csv"]
    y,p,raw,labels=score_files(files,model,cic=True)
    results.append(evaluate("CIC-IDS2017 Friday DDoS + benign morning",y,p,raw,labels))
    out={"protocol":"Frozen V3, thresholds fixed from metadata (0.5, 0.9988); chunked scoring; stratified bootstrap percentile CIs, 1000 reps, 2000 draws/class where available; CIC Friday excludes PortScan and uses DDoS afternoon plus all morning rows.","features":model.features,"results":results}
    (R/"phase_a_raw.json").write_text(json.dumps(out,indent=2),encoding="utf-8")
    print(json.dumps(out,indent=2))
if __name__=="__main__": main()
