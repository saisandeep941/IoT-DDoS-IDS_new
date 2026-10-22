# Phase 2: Original feature and V2 provenance recovery

**Date:** 2026-10-21  
**Scope:** targeted read-only follow-up to `feature_provenance_audit.md`. No training, dataset processing, reconstruction, tests, or external retrieval was performed. The only file created is this report.

## Summary

The historical feature extractor is **not identified**. The protected original's V2 training script reads an already-generated merged CSV; its preprocessing script concatenates exported CSVs and does not generate network-flow features. The focused local file/reference search found no CICFlowMeter JAR/source checkout, PCAP, extractor configuration, or feature-generation script tied to these CSVs. The existing evidence does not prove which implementation generated the training CSVs.

The original V2 procedure and configured input are recoverable, but **actual historical sample membership is not**. The present merged CSV and scripts describe a possible deterministic replay. There is no contemporaneous checksum/runtime record or persisted sampled-row/split manifest connecting that replay to the saved model. Thus replay would be reconstruction only, not proof of historical membership.

## A. Original feature-generation evidence

### Concrete references inspected

- `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\train_model_v2.py` configures `DATA_FILE` as `ml/processed_without_udplag.csv` (line 28). It consumes numeric feature rows; its feature work is column selection and numeric coercion (`:84–108`), not packet/PCAP extraction.
- `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\preprocess.py` points to `dataset/01-12` and writes `processed_without_udplag.csv` (lines 5–6). It reads existing `*.csv` files, excludes `UDPLag.csv`, normalizes columns/labels, replaces infinities, and appends rows (`:11–49`). It contains no extractor invocation, version, build, configuration, or custom-field calculation.
- Original `dataset/01-12` contains ten source CSVs (DrDoS_DNS, DrDoS_LDAP, DrDoS_MSSQL, DrDoS_NetBIOS, DrDoS_NTP, DrDoS_SNMP, DrDoS_SSDP, DrDoS_UDP, Syn, TFTP) and the merged training CSV is present at 22,316,232,040 bytes. The Phase 1 evidence records no source-file manifest or training-time hash for the merged CSV.
- A targeted search of original README/docs/scripts and file names found no locally available CICFlowMeter/custom extractor source, JAR/build, PCAPs, extractor config, or generation manifest. `ml/inspect_false_negatives.py:112–121` references `SimillarHTTP` only as an inspected feature-importance name; it is not generation code. The Phase 1 follow-up already records that the upstream CICFlowMeter source checked does not define the custom fields and cannot establish the `.1` column's lineage.
- The original `.git` directory exists, but Git commands report permission denied. No attempt was made to bypass the restriction. A Git revision present in the later research manifest (`dcadb000727a74836f2877dd7a7aa80afa4ccd66`) identifies that research run, not the historical V2 feature-generation run.

### Four fields

Positions below are one-based positions in the protected serialized schema. Value observations and medians are from the already completed Phase 1 inspection; this phase did not rescan the 22-GB CSV.

| Exact field | Strongest evidence available | Conclusion | Smallest missing evidence |
|---|---|---|---|
| **81 `SimillarHTTP`** | The training CSV contains inspected URL-like strings and numeric-looking `0`. V2 converts with `pd.to_numeric(errors="coerce")` (`train_model_v2.py:106–108`); nonnumeric strings become missing and the fitted imputer median is recorded as 0. The upstream source search and local code search found no definition/calculation. | **Unresolved.** Preprocessing behavior is known; semantic meaning, type/encoding contract, and generation rule are not. | The exact historical exporter/postprocessor source and config that creates this column, plus a fixture documenting its values. |
| **82 `Inbound`** | Inspected input values are integer 0/1 and pass through numeric coercion; the recorded imputer median is 1. No assignment logic appears in the trainer/preprocessor or local generator files. | **Unresolved.** The endpoint/interface/network-boundary reference and direction rule are unknown. | The generator rule or postprocessing source defining “inbound” and the reference point, with a small known-flow fixture. |
| **52 `CWE Flag Count`** | Inspected values are integer 0/1 and the recorded median is 0. Existing source review found a naming discrepancy: CICFlowMeter uses `CWR Flag Count`, while CIC dataset material says `CWE`. No local code resolves the difference. | **Partially supported.** Flag-related numeric behavior is observed, but the TCP bit, count-versus-presence interpretation, and historical implementation are not established. | Pinned generator source or authoritative export documentation resolving CWE/CWR and specifying exactly how packet flags are aggregated. |
| **58 `Fwd Header Length.1`** | Exact suffixed source column is kept as a distinct model input. Existing sampled comparisons found equality with `Fwd Header Length` in the first 10,000 merged rows and first inspected rows from DrDoS_DNS, UDPLag and TFTP; some inspected values are negative; recorded imputer median is 40. | **Partially supported.** Duplicate/suffix origin is plausible, not proven. Sample equality does not establish full-file equivalence or intended meaning. | Original pre-parser header/export code showing how `.1` arose, and either a documented second-field definition or a full comparison plus generator provenance. |

**Extractor identity:** unresolved. None of these records proves that any current/upstream CICFlowMeter build generated the ten historical CSVs. Similar field names or values do not supply that provenance.

## B. V2 training provenance

### Verified historical artifacts and procedure

- Original V2 model: `C:\Users\bonus\Desktop\IoT-DDoS-IDS\backend\real_model_v2.joblib`, 2,205,506 bytes. Original feature list: `...\backend\real_model_features_v2.joblib`, 1,526 bytes. Both are byte-identical to the working copies and match the required hashes below.
- Original `train_model_v2.py` SHA-256 is `1C33B824BC69A9C63FF2CF0589D3B63C92CD9B3F451DBE0479710064B1D3844C`; original `preprocess.py` SHA-256 is `AA166B69635F470DEA7007B7B7CE496C0FBAE3803DAC4F2218923E3F43242428`. These identify the inspected files; no embedded record links one particular execution of them to the model bytes.
- Script configuration and code specify the 22,316,232,040-byte current `processed_without_udplag.csv`, 50,000-row CSV chunks, label mapping (`BENIGN` to 0, all other non-null labels to 1), six excluded columns, first-chunk feature order, numeric coercion/infinity handling, `default_rng(42)` reservoir cap of 100,000 per class, removal of all-missing sampled features, stratified 80/20 `train_test_split(random_state=42)`, median imputation and a balanced 100-tree RF (`train_model_v2.py:28–43, 53–122, 156–215`). The code writes model and feature artifacts to fixed paths at lines 258–264.
- The trainer does not write selected source-row IDs, reservoir membership, split indices, input checksum, package/runtime manifest, or a saved training-test prediction record. No separate validation split is specified in this script.
- `ml/evaluate_model_v2.py` is a later/use-time evaluator of `UDPLag.csv`; it uses a separate 20,000-per-class reservoir (`:19–24, 31–94`) and prints results rather than saving selected row IDs. It does not document the V2 training sample.
- The original `ml/research_results/evaluation_lowmem_20261017` checkpoints and manifest are for a separate 10,000-per-class matched research experiment. Its manifest records the V2 model/schema hashes because V2 was used as a reference in that experiment; this is evidence of later artifact use, not of V2's historical training membership. The working-copy CIC-IDS2017 results similarly describe newly refitted models, not V2.

### Classification of provenance claims

| Claim | Status | Basis / boundary |
|---|---|---|
| The saved working model and feature list are the same bytes as the protected originals and match expected hashes. | **Verified** | Direct read-only SHA-256 comparison of both pairs; model/schema content and prior artifact comparison agree. |
| The inspected V2 training script specifies the algorithm and configured merged input described above. | **Verified as script content** | Read-only source inspection. This does not certify an execution. |
| The saved V2 model was produced by this exact script execution on the current merged CSV bytes. | **Unresolved** | No training-run manifest, input/source hashes captured at fit time, run log binding script to output, or saved membership exists. File timestamps/configuration consistency alone would not prove this. |
| `UDPLag.csv` was excluded from the intended merge procedure. | **Verified as preprocessing-code behavior; historical application conditional** | `preprocess.py:11–14` explicitly excludes that filename. No run manifest binds the present merged file to that invocation. |
| No UDPLag-derived flow/tuple or session could appear in V2's selected data. | **Unresolved** | The excluded source file supports a file-level distinction if the current preprocessing result is the historical input. Cross-file duplicates and session identity were not tested for the historical reservoir; V2 row IDs were not saved. |
| The 80/20 split membership can be recovered exactly from existing saved records. | **Unresolved** | The code specifies a seed/split algorithm but saves no selected rows or indices. The separate research checkpoint is not V2's sample. |
| A replay against current files could reproduce historical membership. | **Reconstruction only, conditional** | It would require preserving the exact input bytes, source row order, NumPy/scikit-learn versions, RNG calls and split behavior. There is no historical checksum/environment anchor against which to validate the result. Do not call it proof. |

The existing UDPLag reference score is not an independent-dataset result. The CIC-IDS2017 benchmark is a separately trained day-held-out study on 78 shared-name features. Neither supplies missing V2 training provenance or validates 82-feature parity.

## C. Integrity and modifications

Read-only hashes were recomputed for original and working-copy artifacts. Each original/working pair agrees and equals the expected value:

| Artifact | Protected original SHA-256 | Working-copy SHA-256 | Expected | Status |
|---|---|---|---|---|
| Random Forest V2 | `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2` | `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2` | same | **PASS** |
| Ordered 82-feature schema | `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28` | `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28` | same | **PASS** |

No code, model, schema, dataset, benchmark output, test, or ZIP was modified. No tests were run because no implementation changed. The only created file is `research/results/feature_provenance_audit/phase2_recovery_report.md`.

## Next actions and final status

1. **Extractor — UNRESOLVED:** obtain the original export bundle from the project author/source archive: custom extractor source or executable with a verifiable build/revision, its configuration/command, and any post-export script that writes the four disputed columns. The concrete trail is the original `dataset/01-12` CSV set consumed by `preprocess.py`; neither that script nor the V2 trainer names the exporter. A generic current CICFlowMeter release is not an adequate substitute.
2. **Historical model membership — UNRESOLVED:** request the original V2 training-run manifest/log containing input CSV SHA-256, source-file order/hashes, software versions, reservoir-selected source row IDs and train/test indices. If that record does not exist, the next possible action is a separately authorized, non-training replay against the archived merged input with a pinned runtime and provenance carried alongside rows. Label it reconstruction; it cannot establish historical membership absent an independent training-time anchor.
3. **Independent V2 evaluation — BLOCKED pending 1 and 2:** after compatible generation and defensible overlap evidence exist, use a separately sourced labeled dataset with all 82 inputs documented. Do not reuse the existing UDPLag results or attribute the CIC-IDS2017 refit metrics to V2.

**Overall status: UNRESOLVED.** The model artifacts and script-level procedure are verified, but the historical feature generator, exact V2 fit-to-input linkage, sampled membership, and flow/session-level independence remain unestablished.
