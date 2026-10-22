# Original Random Forest V2 training artifact comparison

**Result:** The original `train_model_v2.py` is strongly matched to the
protected working-copy V2 artifact. The original model and feature-list files
are byte-identical to the protected working copies, and the serialized model
configuration agrees with the script. The script does not save its selected
row IDs or split membership, so it does not by itself establish row-level
independence for evaluation.

## Read-only artifact identity checks

| Artifact | Original project SHA-256 | Working-copy SHA-256 | Result |
|---|---|---|---|
| `backend/real_model_v2.joblib` vs `model/real_model_v2.joblib` | `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2` | `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2` | Byte-identical |
| `backend/real_model_features_v2.joblib` vs `model/real_model_features_v2.joblib` | `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28` | `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28` | Byte-identical |

Original training script SHA-256: `1C33B824BC69A9C63FF2CF0589D3B63C92CD9B3F451DBE0479710064B1D3844C`.
Original `ml/preprocess.py` SHA-256:
`AA166B69635F470DEA7007B7B7CE496C0FBAE3803DAC4F2218923E3F43242428`.
Both scripts were read only; `train_model_v2.py` was not executed.

Both model copies deserialize as `Pipeline(SimpleImputer, RandomForestClassifier)`;
both have classes `[0, 1]`, 82 inputs, and feature names equal to the 82-item
feature artifact. The imputer is median-based with `keep_empty_features=True`
and `add_indicator=False`. The classifier parameters agree with the script:
100 trees, seed 42, all available jobs, and balanced class weights. This
establishes artifact identity/configuration consistency. It does not create a
training-run manifest embedded in the artifact.

## Recovered training procedure

The full original script is
`C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\train_model_v2.py`. It references:

- Input `ml/processed_without_udplag.csv`, present and 22,316,232,040 bytes.
- Outputs `backend/real_model_v2.joblib` and
  `backend/real_model_features_v2.joblib`; save calls overwrite these paths.
- Chunk size 50,000; maximum reservoir sample 100,000 rows for each class;
  `numpy.random.default_rng(42)`.
- Input labels: drop null labels, strip and uppercase text, map exactly
  `BENIGN` to 0 and every other remaining label to 1.
- Excluded columns: `Label`, `Flow ID`, `Source IP`, `Destination IP`,
  `Timestamp`, and `Unnamed: 0`.
- Feature order: first chunk column order after stripping names and exclusions;
  later chunks are reindexed to it. The actual 88-column input header minus
  those six exclusions equals the saved 82 names in exact order.
- Numeric preprocessing: `pd.to_numeric(errors="coerce")`, then infinities to
  missing values. Columns all-missing in the sampled data are removed before
  the split. Median imputation is fitted as the first pipeline step on training
  data.
- Split: stratified random 80/20 split with `random_state=42`, after sampling;
  no chronological, group, tuple, or session split is applied.
- Estimator: `RandomForestClassifier(n_estimators=100, random_state=42,
  n_jobs=-1, class_weight="balanced")`.

The referenced original `ml/preprocess.py` deletes/rebuilds
`processed_without_udplag.csv` by reading CSVs from `dataset/01-12`, excluding
the file named `UDPLag.csv`, dropping null labels, replacing infinities with
missing values, stripping label whitespace, and appending the rows. Ten
non-UDPLag source CSVs are present in that directory. The V2 training script
does no packet-to-flow feature extraction itself; it consumes these already
generated rows.

## Four priority fields

- **`SimillarHTTP`:** inspected training-source rows are textual, including
  URL-like strings and numeric-looking `0`. The V2 script coerces numeric
  strings and converts other strings to missing; the fitted imputer median is
  0. The effective training representation is partly established, but the
  source field's meaning and generation rule are not.
- **`Inbound`:** inspected training-source rows are integer 0/1 and are passed
  through numeric coercion unchanged; imputer median is 1. The script does not
  define the bit's endpoint/network reference or generation rule.
- **`CWE Flag Count`:** inspected source values are integer 0/1 and are passed
  through numeric coercion unchanged; imputer median is 0. CICFlowMeter's
  README calls the corresponding bit `CWR`; CIC dataset feature documentation
  uses `CWE`. The V2 code does not resolve this naming or the exact bit/count
  implementation.
- **`Fwd Header Length.1`:** the exact column exists in the original source
  headers and is retained as a separate numeric feature; median is 40. It is
  equal to `Fwd Header Length` in the first 10,000 rows of the processed
  training CSV and in the first row of DrDoS_DNS, UDPLag, and TFTP. Inspected
  values include negatives. This supports duplicated values in those records,
  but not the extractor's intended semantics or equality across every training
  row.

The complete 82-entry status list is in
[rf_v2_feature_compatibility.md](rf_v2_feature_compatibility.md). No feature
semantics are inferred from fitted medians alone.

## Saved samples and separation

The V2 training script keeps sampled feature tuples in memory and then calls
`train_test_split`; it never saves the sampled rows, source row numbers, IDs,
split indices, or a V2 training manifest. The merged input retains flow IDs,
IPs, and timestamps before selection, but those columns are excluded before
reservoir sampling and therefore do not identify selected training rows.

The original project has research evaluation artifacts, including
`training_sample.pkl` and `training_sampling_state.pkl`. Their checkpoint
context identifies a separate matched-baseline evaluation (10,000 samples per
class, not V2's 100,000-per-class reservoir). The saved `X` is a 20,000-by-82
feature-only frame, and the sampling state retains feature vectors/priorities
and source-file statistics but not source row IDs. That research run records
12,071 tuple-overlap rows removed in its own protocol; it is not the V2 split
and cannot identify the V2 sample.

Because preprocessing explicitly excludes the UDPLag file, direct reuse of
UDPLag source rows in the V2 input is ruled out by the code path. Row/flow-level
independence is still unproven: there is no V2 selected-row manifest, and
cross-file duplicate tuple/flow exposure has not been resolved for the actual
V2 sample. A precise check requires original V2 selected-row identifiers with
source provenance or a validated exact reconstruction of the seeded reservoir
using the original input bytes, row order, and runtime.

## Evaluation disposition

No evaluation metrics were generated. Exact feature-generation semantics for
the unresolved/custom fields and row/flow-level V2 separation remain blockers.
The existing UDPLag result remains previously used and must not be presented
as a new independent evaluation. The protected model and feature schema were
not modified.
