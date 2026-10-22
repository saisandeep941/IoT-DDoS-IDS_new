# Limitation 1: independent evaluation of Random Forest V2

**Disposition (2026-10-21): blocked.** No new V2 metrics were computed. The available evidence does not support both exact 82-feature compatibility and independence from V2 training data. The frozen model and feature schema were not changed.

The ordered, feature-by-feature compatibility evidence and status inventory are in [the Random Forest V2 feature compatibility review](rf_v2_feature_compatibility.md).

**Evidence update:** The original project folder now confirms the V2 training script, its exact input file, and feature-preprocessing steps; its model and schema files are byte-identical to the protected working-copy artifacts. The training code still does not document the packet/flow extraction semantics for all columns or save V2 row/split identifiers. See [the original artifact comparison](original_v2_training_artifact_comparison.md).

## Findings

### Recovered model artifact metadata

Read-only inspection of the saved V2 artifact confirms an sklearn `Pipeline` with a `SimpleImputer(strategy="median", missing_values=NaN, add_indicator=False, keep_empty_features=True)` followed by a 100-estimator `RandomForestClassifier` (`class_weight="balanced"`, `random_state=42`). Its classes are `[0, 1]`, it expects 82 inputs, and its fitted `feature_names_in_` exactly matches the saved ordered feature file. This recovers the serialized preprocessing/model stages, but not the feature extractor, the pre-imputer transforms, label-source rules, or training row identities.

For the four unresolved columns, serialized imputer medians and forest importances are:

| Feature | Fitted median | RF importance |
|---|---:|---:|
| `SimillarHTTP` | 0 | 0.000000 |
| `Inbound` | 1 | 0.039298 |
| `CWE Flag Count` | 0 | 0.002465 |
| `Fwd Header Length.1` | 40 | 0.001891 |

These are fitted artifact statistics, not feature definitions. They do not disclose how training values were generated or transformed before the imputer.

### Feature definitions

The CICFlowMeter README describes `CWR Flag Count` as packets with CWR, while the CIC dataset feature table labels the corresponding field `CWE Flag Count`/`cwe_cnt` and describes packets with CWE. The exact bit/count semantics used by V2 are therefore not established. CICFlowMeter describes `Fwd Header Length` as header bytes in the forward direction. The sources found do not define `SimillarHTTP` or `Inbound` in the official feature list. The original V2 training data has a `Fwd Header Length.1` column whose inspected values duplicate `Fwd Header Length`, but the generator and full-file semantics remain unverified. The V2 training script does establish that all four fields were numerically coerced (non-numeric `SimillarHTTP` became missing) and median-imputed. The full 82-feature evidence and status inventory is in [the feature compatibility review](rf_v2_feature_compatibility.md).

Sources: [official CICFlowMeter project](https://github.com/ahlashkari/CICFlowMeter), [CICFlowMeter feature-generation overview](https://www.unb.ca/cic/research/applications.html), [CICFlowMeter feature calculation study](https://www.scitepress.org/Papers/2022/107740/pdf/index.html).

The complete local `UDPLag.csv` was inspected in chunks (370,605 rows). Its `SimillarHTTP` column is textual (89 distinct values, including URL-like strings and `0`); `Inbound` is integer 0/1; and `CWE Flag Count` is integer 0/1 in this file. `Fwd Header Length.1` is integer and exactly equals `Fwd Header Length` in all 370,605 rows. This establishes only the representation and equality in the already-used local holdout. It does not establish that these are the V2 training representations or that every 82 input has equivalent semantics. In particular, the current CSV inference path's numeric coercion turns nonnumeric `SimillarHTTP` text into missing values, which the serialized median imputer fills with 0; this is not evidence that such coercion reproduces training-time extraction.

### Candidate dataset review

The project audit identifies local `application/dataset/01-12/UDPLag.csv` as the only available candidate. It belongs to CIC-DDoS2019 and was used in the completed prior evaluation; it is therefore not an unused independent test set. Its official documentation describes PCAP capture, CICFlowMeter-V3 CSV generation, flow labeling using timestamps and network tuple plus attack scenario, and redistribution with citation requirements. These are legitimate provenance and label documentation, but do not cure the reuse or model-specific feature-parity gaps. Source: [official CIC-DDoS2019 page](https://www.unb.ca/cic/datasets/ddos-2019.html).

An unused, legitimate documented candidate is **CSE-CIC-IDS2018**. Its official page documents capture scenarios, CICFlowMeter-V3 extraction, per-flow labeling based on scenario schedule and network identifiers, and redistribution subject to citation. It is a documented candidate, not an established compatible test set: the available material does not demonstrate that its released files contain these exact 82 ordered columns or that the four unresolved fields were generated with V2-equivalent semantics. No candidate data or PCAPs for it are present locally. Source: [official CSE-CIC-IDS2018 page](https://www.unb.ca/cic/datasets/ids-2018.html).

### Overlap and independence

The completed research run manifest and metadata identify ten source CSVs, record their file hashes and source row counts, and document a 60-second forward-time gap plus global bidirectional tuple purging for its **research-only matched baselines**. The holdout is all 370,605 UDPLag rows. This is partial separation evidence for that separate research evaluation only. It is not a V2 training manifest: there are no V2 training-row IDs, sample indices, source hashes, capture/session IDs, or V2 split records. The existing audit states the frozen V2 was trained on later and neighboring CIC-DDoS2019 periods, so its UDPLag result remains a descriptive reference and overlap with the frozen model's training records is unproven. Exact timestamp/tuple or content matching against the baseline run cannot certify V2 non-overlap.

The working copy and submission archive still contain no copy of the original training script or extractor. The script was located in the separate original project folder and inspected read-only. That folder contains the referenced training CSV and other dataset sources, but no V2-specific saved training sample or train/test row indices. Research-run checkpoints found there belong to a different evaluation workflow and do not substitute for V2 sample identifiers.

## Exact blockers and artifacts needed

1. **Feature parity:** the original CICFlowMeter-V3 source/build/configuration and source CSV provenance. For the four priority fields, establish the semantic definition of `SimillarHTTP`, the reference direction for `Inbound`, the CWE/CWR bit counted, and whether `Fwd Header Length.1` is a duplicate field across the complete source rows. The Python preprocessing and the model's serialized imputer/forest are recovered; extractor semantics are not.
2. **Independent candidate compatibility:** the official CSE-CIC-IDS2018 CSV schema plus representative raw rows, or the corresponding PCAPs and an approved extractor, demonstrating each of the exact ordered 82 inputs without guessed mappings. Preserve dataset labels separately and document the binary mapping.
3. **Training overlap audit:** the original preprocessing excludes `UDPLag.csv`, supporting file-level separation, but the V2 script saves no selected sample identifiers or split indices. Provide V2 reservoir row IDs/source provenance or validate deterministic reconstruction from the exact input bytes and runtime. This is needed to check cross-file duplicate flow/tuple exposure; separate research-run tuple purging is not a V2 fit manifest.

Until these artifacts are available, no independent evaluation is defensible. No threshold tuning, retraining, schema coercion, or invented metrics were performed.

## Frozen artifact integrity

SHA-256 values were checked before and after these documentation and docstring changes; canonical and backend copies agree:

| Artifact | SHA-256 |
|---|---|
| Random Forest V2 model (`model/real_model_v2.joblib`; backend copy identical) | `61af42be7f2b079e4bf6fe8d766373cd1d2f91966b28e6bf722810de53f4d9d2` |
| Ordered feature schema (`model/real_model_features_v2.joblib`; backend copy identical) | `c49933abe8df5a693915bd788153bcb7302d75aab486a65e6b07e0a1abcc3e28` |

No evaluation functionality was added, so no tests were added or run for this blocked evaluation request.
