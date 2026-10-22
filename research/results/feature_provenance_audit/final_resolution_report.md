# Final resolution: feature provenance and V2 training reproducibility

**Status: UNRESOLVED.** The available evidence identifies the V2 training algorithm and the configured input, but does not identify the export-time feature generator or prove the actual historical rows used to fit the saved model. No independent V2 evaluation is justified.

## Verified evidence and boundaries

- The original `ml/train_model_v2.py` configures `ml/processed_without_udplag.csv`, numeric coercion, class-wise reservoir sampling (seed 42, at most 100,000 rows per class), a stratified 80/20 split (seed 42), median imputation, and a balanced 100-tree Random Forest. It does not persist source-row IDs, reservoir membership, split indices, input hash, or a contemporaneous run manifest. The script establishes intended procedure, not proof that this exact run produced the protected model.
- Original `ml/preprocess.py` concatenates existing CSV exports from `dataset/01-12` and excludes the file named `UDPLag.csv`. It does not generate flow features or identify the extractor. Without a run-to-model link, the exclusion is conditional evidence about the intended merged input, not proof of historical membership.
- No export-time CICFlowMeter/custom extractor source or executable, build/configuration, post-export transformation, export manifest, or fixture tied to the ten source CSVs was found in the prior targeted recoveries. The exact extractor-to-CSV link is unresolved.
- The four schema fields remain: `CWE Flag Count` (52) partially supported; `Fwd Header Length.1` (58) partially supported; `SimillarHTTP` (81) unresolved; `Inbound` (82) unresolved. Existing observations/coercions are summarized in `feature_provenance_audit.md` and `phase3_source_recovery.md`; observed values do not establish generation semantics.
- No V2 training-run record ties trainer hash, exact input bytes/runtime, and model output hash together. No V2 selected-row or split-membership record was found. Current-file replay would be a reconstruction, not proof of historical membership.
- UDPLag is already used by the V2 reference and same-source research experiments. The CIC-IDS2017 benchmark is a distinct, newly fitted 78-feature research experiment, not V2 evaluation. Neither is independent-dataset validation of frozen V2.
- The research-only UDPLag refit has the documented 60-second temporal gap and direction-independent 5-tuple purge. Capture/session independence remains unverified.

## Feature findings

| Exact field (1-based schema position) | Status | Evidence-supported conclusion | Minimum evidence to resolve |
|---|---|---|---|
| `CWE Flag Count` (52) | Partially supported | Observed values are 0/1; references differ between CWE and CICFlowMeter CWR naming. The precise bit and count/presence aggregation used for these CSVs are unknown. | Export-time generator code or authoritative fixture tied to the historical export, specifying bit and aggregation. |
| `Fwd Header Length.1` (58) | Partially supported | It is a separate ordered numeric model input and matched `Fwd Header Length` in inspected samples. That does not establish full-file equality or why `.1` was emitted. | Raw export header plus linked parser/export/post-processing code and a full-source or fixture-based definition. |
| `SimillarHTTP` (81) | Unresolved | URL-like and numeric-looking values were observed; V2 coerces nonnumeric text to missing and imputes from the fitted median. Meaning/type/generation remain unknown. | Linked generator/post-processing code and a fixture specifying representation and assignment. |
| `Inbound` (82) | Unresolved | Values 0/1 were observed. The interface, endpoint, boundary, and direction rule are unknown. | Linked code/configuration specifying the reference interface/endpoints and assignment rule. |

## Training provenance classification

| Claim | Classification | Reason |
|---|---|---|
| The inspected trainer source describes the stated sampling, split, preprocessing, and RF settings. | Verified as script content | Source code is available, but was not executed as part of this resolution. |
| The configured input path and current original-project CSV/source files exist. | Verified as current artifacts; historical linkage unresolved | No training-time checksum or run record binds their current bytes to the saved model. |
| The saved model was produced by that exact script invocation and input bytes. | Unresolved | No contemporaneous input/runtime/output manifest or training log links them. Matching model identity to the current artifact is not a training record. |
| Exact historical sampled rows and train/test membership are known. | Unresolved | No V2 row IDs, reservoir membership, or split indices were found. |
| UDPLag was excluded at file level by the intended preprocessing script. | Verified as script behavior; conditional historical conclusion | It depends on that invocation producing the precise input used in the model fit. It does not rule out cross-file flow/session overlap. |
| V2 is independently validated on another dataset. | Not established | No independent dataset has verified provenance, labels, exact 82-feature semantics/preprocessing, and defensible separation from V2 training. |

## Prospective resolution plan

For a future, newly recorded training/evaluation run, use the accompanying [provenance protocol](provenance_protocol.md) and [JSON manifest template](provenance_manifest_template.json). Capture hashes and row/split identities at run time; do not backfill estimated values as historical facts.

To resolve the historical gaps, obtain:

1. The exact export-time extractor source revision or binary/build hash, configuration/command, post-export code, and fixture for the four fields.
2. An export manifest linking that exact generator/configuration to each of the ten source CSVs, with source CSV hashes and generation times.
3. A contemporaneous V2 run manifest/log tying trainer hash, exact merged/source input hashes and order, runtime/dependencies, and output model hash together; plus the persisted reservoir row identities and train/test membership. If those membership artifacts were never recorded, historical membership cannot be proven retroactively. A replay is only a labeled reconstruction.
4. Only after feature parity and separation evidence are available, a separately sourced, labeled dataset with documented all-82 feature generation and auditable non-overlap.

## Claim guidance

Use: “The inspected V2 trainer specifies a seeded reservoir sample and stratified split over a configured merged CSV. Available artifacts do not link that procedure to exact historical model-training bytes or row membership. A separate research-only UDPLag experiment used a 60-second gap and tuple purge, but capture/session independence is unverified. No independent-dataset evaluation of frozen V2 has been established.”

Do not state that V2's historical fit definitely included later or neighboring UDPLag rows. The available trainer/input evidence does not establish actual saved-model membership. Do not describe the CIC-IDS2017 refit as V2 evaluation.

## Integrity and changes

Working-copy model and schema SHA-256 checks passed at resolution time:

- `model/real_model_v2.joblib`: `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2`
- `model/real_model_features_v2.joblib`: `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28`
- Backend runtime copies have the same respective hashes.

No model, schema, dataset, application code, benchmark output, tests, or ZIP was changed. Documentation corrections and prospective records are listed in the completion response.
