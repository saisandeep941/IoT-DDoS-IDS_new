"""Local V3 model/API resource benchmark; writes only under results_v31."""
from __future__ import annotations
import argparse, csv, json, os, statistics, sys, threading, time
from pathlib import Path
from urllib.request import Request, urlopen
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/'research'/'results_v31'
sys.path.insert(0,str(ROOT/'model_v3'))
sys.path.insert(0,str(ROOT/'research'/'code'))
from v3_loader import V3Model

SOURCE=Path(r'C:\Users\bonus\Desktop\CICDDoS2019-03-11-Test\UDPLag.csv')

def percentile(xs): return {f'p{q}':float(np.percentile(xs,q)) for q in (50,95,99)}

def load_probe(v3,limit):
    with SOURCE.open('r',encoding='utf-8-sig',newline='') as f: raw=next(csv.reader(f))
    names=[x.strip() for x in raw]; use=[raw[names.index(n)] for n in v3.features]
    chunks=[];n=0
    for chunk in pd.read_csv(SOURCE,usecols=use,chunksize=25_000,low_memory=False):
        chunk.columns=[x.strip() for x in chunk.columns]; chunks.append(chunk);n+=len(chunk)
        if n>=limit: break
    frame=pd.concat(chunks,ignore_index=True).iloc[:limit]
    return v3.prepare(frame)

def run_model(v3,X,repeats):
    one=X.iloc[[0]]
    for _ in range(20):v3.model.predict_proba(one)
    lat=[]
    start_cpu=time.process_time();start=time.perf_counter()
    for _ in range(repeats):
        t=time.perf_counter_ns();v3.model.predict_proba(one);lat.append((time.perf_counter_ns()-t)/1e6)
    latency_duration=time.perf_counter()-start
    batch=[]
    for _ in range(3):
        t=time.perf_counter()
        for offset in range(0,len(X),8192):v3.model.predict_proba(X.iloc[offset:offset+8192])
        batch.append(time.perf_counter()-t)
    return {'single_row_latency_ms':percentile(lat),'single_row_repeats':repeats,'throughput_rows_per_second':float(len(X)/statistics.median(batch)),'batch_rows':len(X),'batch_repeats':3,'process_cpu_seconds':float(time.process_time()-start_cpu),'latency_loop_seconds':latency_duration}

def api_bench(url,values,repeats,key):
    payload=json.dumps({'features':values}).encode()
    headers={'Content-Type':'application/json'}
    if key:headers['X-API-Key']=key
    times=[]
    for _ in range(10):
        with urlopen(Request(url,data=payload,headers=headers,method='POST'),timeout=30) as response:
            if response.status!=200: raise RuntimeError(f'API returned HTTP {response.status}')
            response.read()
    for _ in range(repeats):
        t=time.perf_counter_ns()
        with urlopen(Request(url,data=payload,headers=headers,method='POST'),timeout=30) as response:
            if response.status!=200:raise RuntimeError(f'API returned HTTP {response.status}')
            response.read()
        times.append((time.perf_counter_ns()-t)/1e6)
    return {'endpoint':url,'warmup_requests':10,'measured_requests':repeats,'end_to_end_latency_ms':percentile(times),'scope':'local loopback HTTP including request parsing, V3 artifact loading, inference and JSON response'}

def constrained_probe(v3,X,repeats):
    result={'label':'emulated constrained environment on a laptop, not real IoT hardware','cpu_affinity':'unavailable','memory_job_object':'unavailable'}
    try:
        import psutil
        process=psutil.Process(); old=process.cpu_affinity(); process.cpu_affinity([old[0]])
        result['cpu_affinity']={'applied_cpu_ids':[old[0]],'original_cpu_count':len(old)}
        try:
            import ctypes
            from ctypes import wintypes
            class BASIC(ctypes.Structure):
                _fields_=[('PerProcessUserTimeLimit',ctypes.c_longlong),('PerJobUserTimeLimit',ctypes.c_longlong),('LimitFlags',wintypes.DWORD),('MinimumWorkingSetSize',ctypes.c_size_t),('MaximumWorkingSetSize',ctypes.c_size_t),('ActiveProcessLimit',wintypes.DWORD),('Affinity',ctypes.c_size_t),('PriorityClass',wintypes.DWORD),('SchedulingClass',wintypes.DWORD)]
            class IO(ctypes.Structure):
                _fields_=[('ReadOperationCount',ctypes.c_ulonglong),('WriteOperationCount',ctypes.c_ulonglong),('OtherOperationCount',ctypes.c_ulonglong),('ReadTransferCount',ctypes.c_ulonglong),('WriteTransferCount',ctypes.c_ulonglong),('OtherTransferCount',ctypes.c_ulonglong)]
            class EXT(ctypes.Structure):
                _fields_=[('BasicLimitInformation',BASIC),('IoInfo',IO),('ProcessMemoryLimit',ctypes.c_size_t),('JobMemoryLimit',ctypes.c_size_t),('PeakProcessMemoryUsed',ctypes.c_size_t),('PeakJobMemoryUsed',ctypes.c_size_t)]
            k=ctypes.WinDLL('kernel32',use_last_error=True)
            k.CreateJobObjectW.argtypes=[wintypes.LPVOID,wintypes.LPCWSTR];k.CreateJobObjectW.restype=wintypes.HANDLE
            k.SetInformationJobObject.argtypes=[wintypes.HANDLE,wintypes.INT,ctypes.c_void_p,wintypes.DWORD];k.SetInformationJobObject.restype=wintypes.BOOL
            k.GetCurrentProcess.argtypes=[];k.GetCurrentProcess.restype=wintypes.HANDLE
            k.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE];k.AssignProcessToJobObject.restype=wintypes.BOOL
            k.CloseHandle.argtypes=[wintypes.HANDLE];k.CloseHandle.restype=wintypes.BOOL
            handle=k.CreateJobObjectW(None,None)
            if not handle:raise OSError(ctypes.get_last_error(),'CreateJobObject failed')
            info=EXT();info.BasicLimitInformation.LimitFlags=0x100;info.ProcessMemoryLimit=2*1024*1024*1024
            if not k.SetInformationJobObject(handle,9,ctypes.byref(info),ctypes.sizeof(info)):raise OSError(ctypes.get_last_error(),'SetInformationJobObject failed')
            if not k.AssignProcessToJobObject(handle,k.GetCurrentProcess()):raise OSError(ctypes.get_last_error(),'AssignProcessToJobObject failed')
            result['memory_job_object']={'applied':True,'process_memory_cap_bytes':info.ProcessMemoryLimit}
            k.CloseHandle(handle)
        except Exception as error: result['memory_job_object']={'applied':False,'reason':f'{type(error).__name__}: {error}'}
        result['model_benchmark']=run_model(v3,X,repeats)
        process.cpu_affinity(old)
    except Exception as error:result['error']=f'{type(error).__name__}: {error}'
    return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--api-url');parser.add_argument('--rows',type=int,default=50000);parser.add_argument('--repeats',type=int,default=100);args=parser.parse_args()
    v3=V3Model();X=load_probe(v3,args.rows)
    try:
        import psutil
        proc=psutil.Process();memory_before=int(proc.memory_info().rss);cpu_before=proc.cpu_percent(interval=.1)
    except ImportError:proc=None;memory_before=None;cpu_before=None
    model=run_model(v3,X,args.repeats)
    if proc:memory_after=int(proc.memory_info().rss);cpu_after=float(proc.cpu_percent(interval=.1))
    else:memory_after=None;cpu_after=None
    result={'environment':'emulated constrained environment on a laptop, not real IoT hardware','model_only':model,'process_memory_before_bytes':memory_before,'process_memory_after_bytes':memory_after,'process_cpu_percent_samples':[cpu_before,cpu_after],'source_rows_for_benchmark':len(X),'source_file':str(SOURCE),'constrained':constrained_probe(v3,X,args.repeats)}
    if args.api_url:result['api']=api_bench(args.api_url,X.iloc[0].to_list(),100,os.getenv('SENTINEL_API_KEY'))
    (OUT/'phase_d_benchmark.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    pd.DataFrame([{'scope':'model_only',**model},*([{'scope':'api',**result['api']['end_to_end_latency_ms']}] if 'api' in result else [])]).to_csv(OUT/'phase_d_benchmark.csv',index=False)
    lines=['# Phase D — V3 resource benchmark','',f"- Environment: {result['environment']}",f"- Model-only p50/p95/p99: {model['single_row_latency_ms']}",f"- Batch throughput: {model['throughput_rows_per_second']} rows/s",f"- Process memory before/after: {memory_before}, {memory_after} bytes",f"- Constrained run: {result['constrained']}"]
    if 'api' in result:lines.append(f"- End-to-end API p50/p95/p99 ms: {result['api']['end_to_end_latency_ms']}")
    (OUT/'phase_d_benchmark.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
