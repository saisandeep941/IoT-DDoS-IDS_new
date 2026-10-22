# Phase 4: Targeted local artifact recovery

**Date:** 2026-10-21  
**Scope:** one targeted pass over the report-named working-copy and original-project locations. No unrestricted drive search, Git permission bypass, training, dataset scan, or external search was performed.

## Outcome

No original CICFlowMeter/custom extractor implementation, build, configuration, or export-to-CSV manifest was recovered. The original V2 trainer, configured merged CSV, and several later research artifacts exist in the protected original, but none ties exact historical input bytes or sampled/split row identities to the saved V2 model. The targeted recovery therefore leaves the four field-generation questions and historical V2 membership unresolved.

## Artifact findings

| Candidate | Status and exact location | SHA-256 / size | What it establishes; what it does not |
|---|---|---|---|
| CICFlowMeter/custom extractor source, built JAR, source archive, version/build metadata, config, PCAPs, post-export generator or fixtures | **Not found** in the working copy's file inventory or the Phase 3 targeted name inventory. No such item appeared in the Phase 4 immediate listings of original `ml/` or `dataset/01-12/`. The existing reports do not name a concrete extractor archive path. | N/A | No executable source is available to trace the four fields or to link an extractor to the historical CSV exports. This finding is limited to the named project locations and prior project-file inventory; no unrelated drive was searched. |
| Original `ml/preprocess.py` | **Found** at `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\preprocess.py`; inspected in prior phases, not executed. | SHA-256 `AA166B69635F470DEA7007B7B7CE496C0FBAE3803DAC4F2218923E3F43242428`; 2,043 bytes (Phase 1 inventory). | It concatenates existing CSVs, excludes `UDPLag.csv`, normalizes labels/columns, and writes the merged file. It is an aggregation step, not the flow feature extractor, and has no extractor version/config or export manifest. |
| Original `ml/train_model_v2.py` | **Found** at `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\train_model_v2.py`; read-only. | SHA-256 `1C33B824BC69A9C63FF2CF0589D3B63C92CD9B3F451DBE0479710064B1D3844C`; 7,165 bytes (Phase 1 inventory). | Establishes intended training code/settings. It consumes `processed_without_udplag.csv`; it does not generate CICFlowMeter fields or persist a run manifest, row identities, reservoir membership, or split indices. Its hash identifies the current script file, not the historical run. |
| Original merged training input | **Found** at `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\processed_without_udplag.csv`. | 22,316,232,040 bytes. No digest calculated in this pass: this is a 22-GB read, and no training-time expected digest exists to compare. | Establishes a current candidate input at the configured path. It is not linked to the model's historical fit by a saved hash or run record. |
| Original source CSV set | **Found** in `C:\Users\bonus\Desktop\IoT-DDoS-IDS\dataset\01-12\`: `DrDoS_DNS.csv`, `DrDoS_LDAP.csv`, `DrDoS_MSSQL.csv`, `DrDoS_NetBIOS.csv`, `DrDoS_NTP.csv`, `DrDoS_SNMP.csv`, `DrDoS_SSDP.csv`, `DrDoS_UDP.csv`, `Syn.csv`, `TFTP.csv`, plus `UDPLag.csv`. | The prior inventory records file sizes. The available research manifest records source paths, sizes, and mtimes, but no SHA-256 for these CSVs. | Confirms candidate source files and filenames. The preprocessor's code excludes the UDPLag filename, but there is no generation manifest tying these present copies to the historical merge/model fit or identifying the exporter. Cross-file flow/session overlap remains untested. |
| `recover_medians.py` | **Found** at `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\recover_medians.py`; read-only inspection only. | SHA-256 `00F0A7131D5AEEC4915A6A1D656591216FF4F8925A1A9FDCC153FEC798E67284`; 2,000 bytes. | Replays a 100,000-per-class reservoir with seed 42 against the current merged CSV, but loads `backend/real_model_features.joblib` (without `_v2`) and writes medians only. It does not save sampled row IDs or split membership and is not tied to the V2 model's historical fit. It is a possible later reconstruction helper, not historical evidence. It was not run. |
| `recovered_medians.joblib` | **Found** at `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\recovered_medians.joblib`. | SHA-256 `D0EF3FD33BEA82E5085528A4CF293E9A9C7896A5F25CAB3BCD1C3ED9F8904E00`; 2,264 bytes. | A saved medians dictionary from the helper's stated purpose. It contains neither row identities nor split indices and does not show the source bytes/runtime used or bind the medians to the protected V2 training execution. |
| Later research `run_manifest.json` | **Found** at `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\research_results\evaluation_lowmem_20261017\run_manifest.json`. | SHA-256 `21C766D537ACAA03BA2916B2FE345DD22A230C338921E44B8E1D3A8D4D8BC93C`; 7,795 bytes. | Records the V2 model and feature-file hashes as artifacts used in a completed later evaluation, research-script hashes, a 10,000-per-class configuration, and source CSV paths/sizes/mtimes. Its fingerprints contain no source CSV SHA-256, and its trainer code hashes are for `evaluate_research.py` and `research_eval_protocol.py`, not `train_model_v2.py`. It is not the V2 training manifest. |
| Later research checkpoints `training_sample.pkl`, `training_sampling_state.pkl` | **Found** under `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\research_results\evaluation_lowmem_20261017\checkpoints\`. | Sample: 13,146,783 bytes, SHA-256 `FD292DB36EC31E6391F0FE48F914C7B122723A04EAB3DBC05233B4F57DD644C1`. State: 13,285,933 bytes, SHA-256 `05D31356225B4A371F3A191D62013D01ACA10C406DC840CB886BC9E620877650`. | Prior artifact inspection identifies these as a separate 10,000-per-class research experiment, not V2's 100,000-per-class reservoir; they do not contain V2 membership. Their own hashes authenticate these checkpoint files, not the original V2 run. |
| Original Git object history | `.git` directory existence was recorded in Phase 2; `git -C C:\Users\bonus\Desktop\IoT-DDoS-IDS ...` returned **access denied**. | Not available. | No commit objects or history were inspected. No access-control bypass was attempted. The research manifest's Git revision identifies the later research run only. |
| Working-copy frozen model and schema | **Found** at `model/real_model_v2.joblib` and `model/real_model_features_v2.joblib`. | Model SHA-256 `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2`; schema SHA-256 `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28`. | Hashes match the required values. Phase 2 also verified original/working-copy equality. This verifies artifact identity, not historical sample membership. |

## Feature and training conclusions

No new evidence changes the Phase 3 feature status:

| Feature | Status | Remaining evidence gap |
|---|---|---|
| `SimillarHTTP` (schema position 81) | **Unresolved** | Historical generator/post-export code and a fixture documenting meaning, type/encoding, and assignment. |
| `Inbound` (position 82) | **Unresolved** | Rule identifying the network/interface/endpoint reference and its 0/1 assignment. |
| `CWE Flag Count` (position 52) | **Partially supported** | Exact CWE-versus-CWR bit and whether the value is a packet count or presence indicator, from the historical generator. |
| `Fwd Header Length.1` (position 58) | **Partially supported** | Export-time header handling/postprocessor that generated the suffix, and full-source or documented semantics for this distinct model input. |

**Historical V2 membership: not established.** The V2 trainer script and current merged input are not a contemporaneous training record. `recover_medians.py` and the saved research checkpoints do not recover V2 membership. The later manifest associates the expected model/schema hashes with a later reference evaluation; it does not bind the saved model to a specific training execution or exact input bytes. No training log, training-time CSV digest, V2 reservoir row identities, or split-index artifact was found in the checked locations.

The later research manifest provides only source-file sizes and modification times for its evaluation inputs, not hashes, and it concerns a different run. It cannot be promoted to V2 provenance. The presence of a reproducible seed and split function in code remains insufficient to claim which rows produced the saved model.

## Exact next artifacts needed

1. **Feature generator:** provide the export-time CICFlowMeter/custom extractor source revision or executable/JAR with build/version and SHA-256; its config and invocation; and every wrapper/post-export script that generated or renamed columns. Include a small fixture or documented code path for the four fields.
2. **Export linkage:** provide an export manifest/log mapping that exact generator build/config to each of the ten named `dataset/01-12` CSVs, with generation dates and CSV checksums. A current extractor source without this link is only a possible substitute.
3. **V2 run linkage and membership:** provide a contemporaneous trainer log/manifest tying trainer-code hash, exact merged-input and source-file hashes/order, dependency versions, and model-output hash together, plus saved reservoir source-row identities and split indices. If row membership was never persisted, a replay against archived inputs can only be described as reconstruction, not verified historical membership.

## Changes and final status

Only `research/results/feature_provenance_audit/phase4_local_artifact_recovery.md` was created. No original or working project artifacts, datasets, benchmark outputs, tests, or ZIP files were modified; no tests or training were run.

- Original extractor and historical CSV link: **UNRESOLVED**.
- Four feature definitions: **two unresolved; two partially supported**.
- Exact V2 training input/run linkage and row/split membership: **UNRESOLVED**.
- Model/schema integrity: **VERIFIED** against required hashes (and original/working equality recorded in Phase 2).
