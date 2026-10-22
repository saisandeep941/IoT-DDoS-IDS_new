# Random Forest V2: ordered 82-feature compatibility review

**Disposition:** No feature is marked **Verified compatible**. The saved model
and schema establish the names, order, numeric model-input requirement, and
serialized median imputation, but not the feature extractor or exact training
preprocessing. The status below distinguishes publicly documented meaning from
compatibility with the unavailable V2 training pipeline.

## Status definitions and evidence scope

- **Verified compatible:** exact name, order, type, units, calculation, and
  preprocessing agree with the V2 training pipeline and candidate data. No
  feature meets this standard with current evidence.
- **Partially verified:** an official CICFlowMeter/CIC dataset reference gives
  a meaning close to the column name or the original training inputs establish
  some representation/value behavior, but exact V2 generation semantics,
  formula conventions, or source-level provenance remain incomplete.
- **Unresolved:** the authoritative references found do not define the V2
  feature, or the name is ambiguous in a way that prevents a defensible mapping.

The ordered names below come from `model/real_model_features_v2.joblib` (82
unique entries; SHA-256
`C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28`). The
official CICFlowMeter README documents the standard statistics, including its
first-packet forward/backward convention and configurable flow timeout. The
CSE-CIC-IDS2018 page documents CICFlowMeter-V3 extraction and a separate 80+
feature export. Neither establishes that V2 used the same version, options,
column construction, type coercion, or preprocessing. Generic numeric
interpretations below therefore remain **Partially verified**, not proof of
V2 compatibility.

## Ordered feature inventory

| # | Exact schema name | Documented meaning available | Status |
|---:|---|---|---|
| 1 | `Source Port` | Source transport port; exact encoding/type in V2 preprocessing not recorded. | Partially verified |
| 2 | `Destination Port` | Destination transport port; exact encoding/type in V2 preprocessing not recorded. | Partially verified |
| 3 | `Protocol` | Protocol field is documented in CIC dataset flow metadata; V2 numeric encoding is not recorded. | Partially verified |
| 4 | `Flow Duration` | Duration of a flow; CICFlowMeter README says microseconds, but V2 extractor/version and unit are not established. | Partially verified |
| 5 | `Total Fwd Packets` | Number of packets in forward direction. | Partially verified |
| 6 | `Total Backward Packets` | Number of packets in backward direction. | Partially verified |
| 7 | `Total Length of Fwd Packets` | Total packet size in forward direction. | Partially verified |
| 8 | `Total Length of Bwd Packets` | Total packet size in backward direction. | Partially verified |
| 9 | `Fwd Packet Length Max` | Maximum packet size in forward direction. | Partially verified |
| 10 | `Fwd Packet Length Min` | Minimum packet size in forward direction. | Partially verified |
| 11 | `Fwd Packet Length Mean` | Mean packet size in forward direction. | Partially verified |
| 12 | `Fwd Packet Length Std` | Standard deviation of packet size in forward direction. | Partially verified |
| 13 | `Bwd Packet Length Max` | Maximum packet size in backward direction. | Partially verified |
| 14 | `Bwd Packet Length Min` | Minimum packet size in backward direction. | Partially verified |
| 15 | `Bwd Packet Length Mean` | Mean packet size in backward direction. | Partially verified |
| 16 | `Bwd Packet Length Std` | Standard deviation of packet size in backward direction. | Partially verified |
| 17 | `Flow Bytes/s` | Flow byte rate per second; exact byte definition and zero-duration handling not recorded for V2. | Partially verified |
| 18 | `Flow Packets/s` | Flow packet rate per second; exact zero-duration handling not recorded for V2. | Partially verified |
| 19 | `Flow IAT Mean` | Mean inter-arrival time between packets in a flow. | Partially verified |
| 20 | `Flow IAT Std` | Standard deviation of packet inter-arrival times in a flow. | Partially verified |
| 21 | `Flow IAT Max` | Maximum packet inter-arrival time in a flow. | Partially verified |
| 22 | `Flow IAT Min` | Minimum packet inter-arrival time in a flow. | Partially verified |
| 23 | `Fwd IAT Total` | Total inter-arrival time for forward packets. | Partially verified |
| 24 | `Fwd IAT Mean` | Mean inter-arrival time for forward packets. | Partially verified |
| 25 | `Fwd IAT Std` | Standard deviation of forward packet inter-arrival times. | Partially verified |
| 26 | `Fwd IAT Max` | Maximum forward packet inter-arrival time. | Partially verified |
| 27 | `Fwd IAT Min` | Minimum forward packet inter-arrival time. | Partially verified |
| 28 | `Bwd IAT Total` | Total inter-arrival time for backward packets. | Partially verified |
| 29 | `Bwd IAT Mean` | Mean inter-arrival time for backward packets. | Partially verified |
| 30 | `Bwd IAT Std` | Standard deviation of backward packet inter-arrival times. | Partially verified |
| 31 | `Bwd IAT Max` | Maximum backward packet inter-arrival time. | Partially verified |
| 32 | `Bwd IAT Min` | Minimum backward packet inter-arrival time. | Partially verified |
| 33 | `Fwd PSH Flags` | Count of forward packets with PSH set; CICFlowMeter describes zero for UDP. | Partially verified |
| 34 | `Bwd PSH Flags` | Count of backward packets with PSH set; CICFlowMeter describes zero for UDP. | Partially verified |
| 35 | `Fwd URG Flags` | Count of forward packets with URG set; CICFlowMeter describes zero for UDP. | Partially verified |
| 36 | `Bwd URG Flags` | Count of backward packets with URG set; CICFlowMeter describes zero for UDP. | Partially verified |
| 37 | `Fwd Header Length` | Total bytes used for headers in forward direction. | Partially verified |
| 38 | `Bwd Header Length` | Total bytes used for headers in backward direction. | Partially verified |
| 39 | `Fwd Packets/s` | Forward packet rate per second. | Partially verified |
| 40 | `Bwd Packets/s` | Backward packet rate per second. | Partially verified |
| 41 | `Min Packet Length` | Minimum packet length in the flow. | Partially verified |
| 42 | `Max Packet Length` | Maximum packet length in the flow. | Partially verified |
| 43 | `Packet Length Mean` | Mean packet length in the flow. | Partially verified |
| 44 | `Packet Length Std` | Standard deviation of packet length in the flow. | Partially verified |
| 45 | `Packet Length Variance` | Variance of packet length in the flow. | Partially verified |
| 46 | `FIN Flag Count` | Number of packets with FIN set. | Partially verified |
| 47 | `SYN Flag Count` | Number of packets with SYN set. | Partially verified |
| 48 | `RST Flag Count` | Number of packets with RST set. | Partially verified |
| 49 | `PSH Flag Count` | Number of packets with PSH set. | Partially verified |
| 50 | `ACK Flag Count` | Number of packets with ACK set. | Partially verified |
| 51 | `URG Flag Count` | Number of packets with URG set. | Partially verified |
| 52 | `CWE Flag Count` | CICFlowMeter references disagree in spelling: its feature table says CWR count while dataset material says CWE; exact bit/count semantics used by V2 are not proved. | Partially verified |
| 53 | `ECE Flag Count` | Number of packets with ECE set. | Partially verified |
| 54 | `Down/Up Ratio` | Download/upload ratio; numerator/denominator direction is not established for V2. | Partially verified |
| 55 | `Average Packet Size` | Average packet size. | Partially verified |
| 56 | `Avg Fwd Segment Size` | Average segment size in forward direction. | Partially verified |
| 57 | `Avg Bwd Segment Size` | Average segment size in backward direction. | Partially verified |
| 58 | `Fwd Header Length.1` | Explicitly present in original CIC-DDoS2019 source headers. It equals `Fwd Header Length` in the first 10,000 processed training rows and first row of DrDoS_DNS, UDPLag, and TFTP; checked values include negatives, so header-byte semantics are questionable. Full-data generation lineage is unavailable. | Partially verified |
| 59 | `Fwd Avg Bytes/Bulk` | Average bytes per bulk in forward direction. | Partially verified |
| 60 | `Fwd Avg Packets/Bulk` | Average packets per bulk in forward direction. | Partially verified |
| 61 | `Fwd Avg Bulk Rate` | Average bulk rate in forward direction. | Partially verified |
| 62 | `Bwd Avg Bytes/Bulk` | Average bytes per bulk in backward direction. | Partially verified |
| 63 | `Bwd Avg Packets/Bulk` | Average packets per bulk in backward direction. | Partially verified |
| 64 | `Bwd Avg Bulk Rate` | Average bulk rate in backward direction. | Partially verified |
| 65 | `Subflow Fwd Packets` | Average packet count in a forward subflow. | Partially verified |
| 66 | `Subflow Fwd Bytes` | Average byte count in a forward subflow. | Partially verified |
| 67 | `Subflow Bwd Packets` | Average packet count in a backward subflow. | Partially verified |
| 68 | `Subflow Bwd Bytes` | Average byte count in a backward subflow. | Partially verified |
| 69 | `Init_Win_bytes_forward` | Bytes sent in the initial forward window. | Partially verified |
| 70 | `Init_Win_bytes_backward` | Bytes sent in the initial backward window. | Partially verified |
| 71 | `act_data_pkt_fwd` | Count of forward packets with at least one byte of TCP data payload. | Partially verified |
| 72 | `min_seg_size_forward` | Minimum segment size observed in forward direction. | Partially verified |
| 73 | `Active Mean` | Mean time a flow is active before becoming idle. | Partially verified |
| 74 | `Active Std` | Standard deviation of active times before becoming idle. | Partially verified |
| 75 | `Active Max` | Maximum active time before becoming idle. | Partially verified |
| 76 | `Active Min` | Minimum active time before becoming idle. | Partially verified |
| 77 | `Idle Mean` | Mean time a flow is idle before becoming active. | Partially verified |
| 78 | `Idle Std` | Standard deviation of idle times before becoming active. | Partially verified |
| 79 | `Idle Max` | Maximum idle time before becoming active. | Partially verified |
| 80 | `Idle Min` | Minimum idle time before becoming active. | Partially verified |
| 81 | `SimillarHTTP` | No authoritative feature definition found in CICFlowMeter documentation; the local holdout column is textual and becomes missing under current numeric coercion. | Unresolved |
| 82 | `Inbound` | Local holdout values are integer 0/1, but no authoritative definition of what the bit is relative to was found. | Unresolved |

### Four priority features

- **`SimillarHTTP`: unresolved.** No authoritative field definition, data type,
  encoding, or generation method for V2 was located. The fitted model's median
  is zero; this only describes its imputer.
- **`Inbound`: unresolved.** Local values are 0/1, but the interface/direction
  reference and assignment rule are undocumented for the V2 extractor.
- **`CWE Flag Count`: partially verified.** Documentation establishes a
  flag-count concept, but source material alternates between CWE and CWR.
  The exact TCP bit and counting implementation used for V2 are not proved.
- **`Fwd Header Length.1`: partially verified.** The original source CSVs
  contain this exact suffixed field and the checked training/source rows equal
  `Fwd Header Length`. Its full-dataset equality and extractor lineage are not
  documented, and checked values include negative values despite the documented
  header-byte meaning.

## Recovered V2 training pipeline and candidate data

Read-only inspection of `C:\Users\bonus\Desktop\IoT-DDoS-IDS\ml\train_model_v2.py`
and its referenced artifacts establishes the following pipeline. The script
reads `ml/processed_without_udplag.csv` in 50,000-row chunks, strips header
whitespace, drops null `Label` rows, maps case/whitespace-normalized `BENIGN`
to 0 and every other non-null label to 1, and replaces infinities with missing
values. It excludes `Label`, `Flow ID`, `Source IP`, `Destination IP`,
`Timestamp`, and `Unnamed: 0`. The first chunk's remaining CSV column order
becomes the feature order; later chunks are reindexed to that order. Each input
feature is passed through `pd.to_numeric(errors="coerce")`, then infinities
are replaced with missing values. A seeded (`default_rng(42)`) reservoir
retains at most 100,000 rows per class. Features entirely missing in that
sample are removed. The sample is randomly stratified into 80% train and 20%
test (`random_state=42`). The fitted pipeline is median `SimpleImputer`
(`keep_empty_features=True`) plus `RandomForestClassifier(n_estimators=100,
random_state=42,n_jobs=-1,class_weight="balanced")`; it is saved by overwriting
the referenced backend model and feature-list paths. No train/test identifiers
or split indices are saved by this script.

The inspected original `train_model_v2.py` SHA-256 is recorded in the separate
artifact comparison report; the script was read, not executed.

The referenced `ml/processed_without_udplag.csv` exists in the original project
(22,316,232,040 bytes). Its header has 88 columns; applying the six exclusions
leaves 82 names in exactly the saved schema order. The original preprocessing
script rebuilds that file from every CSV in `dataset/01-12` except `UDPLag.csv`.
The original project has ten such non-UDPLag source CSVs. The model and
`backend/real_model_features_v2.joblib` are byte-identical to the protected
working-copy artifacts; their hashes are respectively
`61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2` and
`C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28`. The
serialized pipeline parameters and `feature_names_in_` agree with the script
and feature artifact. Thus the script/artifact correspondence is strongly
supported by exact artifact identity and configuration, though the artifacts
do not contain an embedded training-run manifest.

The script establishes how the four fields enter the model, but not their
packet/flow generation semantics:

- **`SimillarHTTP`:** original training input is textual in inspected rows,
  with both numeric-looking `0` and URL-like values. Numeric coercion accepts
  numeric strings and converts nonnumeric strings to missing; the fitted
  median is 0, so missing values are imputed to 0. This recovers its effective
  model representation, not the meaning or generation rule of the source field.
- **`Inbound`:** inspected values are integer 0/1 and are numerically passed
  unchanged; fitted median is 1. The script does not define which endpoint or
  network boundary the bit means.
- **`CWE Flag Count`:** inspected values are integer 0/1 and are numerically
  passed unchanged; fitted median is 0. The CICFlowMeter README calls the
  corresponding bit CWR, while dataset documentation calls it CWE. The script
  does not resolve the bit name or packet counting rule.
- **`Fwd Header Length.1`:** it is included as its own numeric column; fitted
  median is 40. The field equals `Fwd Header Length` in the first 10,000 rows
  of the processed training CSV and in the first row of DrDoS_DNS, UDPLag, and
  TFTP. That is evidence of duplicated values in those inspected records, not
  proof of the extractor's intent or equality throughout the full training
  file; the inspected values include negatives.

The V2 source CSV list confirms CIC-DDoS2019-style files; the separate research
manifest/checkpoints belong to a later matched-baseline run, not this V2 fit.
Those research artifacts include a 20,000-row feature-only sample and report
12,071 rows removed for tuple overlap in that separate protocol. They contain
no V2 sample IDs and cannot identify which records entered V2 training.

The only local candidate remains `UDPLag.csv`; it was previously used for
evaluation/threshold comparisons. `preprocess.py` excludes that entire source
file from the V2 input, which supports direct file-level holdout. It does not
prove that duplicate flows/tuples in other source files were absent from the
V2 reservoir sample. CSE-CIC-IDS2018 is documented as a separate legitimate
release using CICFlowMeter-V3, with scenario/endpoint-based labels and
redistribution allowed subject to citation, but its published feature export
is not established as the exact V2 schema and it does not document V2's
`SimillarHTTP`/`Inbound` generation. It is therefore not presently a usable
test set for this frozen model.

## Separation conclusion and evidence needed

Independence from V2 training is **partially supported at the source-file
level for UDPLag, but unproven at row/flow level**. The preprocessing code
explicitly excludes `UDPLag.csv`, while the V2 script draws its reservoir from
the resulting merged CSV. However, the V2 script discards all source-row IDs
before sampling and saves no selected row IDs or split indices, and the
separate research artifacts show that tuple-level overlap exists in the
cross-file evaluation setting. A reproducible V2-specific overlap check needs
the selected V2 training rows/indices with source file and row/flow identity,
or exact-environment deterministic reconstruction of the seeded reservoir
from the exact input file plus evidence that its bytes and sampling runtime
match the original run.

Independent evaluation was not run. Minimum evidence required to proceed:

1. The original CICFlowMeter-V3 source/build/configuration used to generate the
   CIC-DDoS2019 source CSVs, plus evidence defining `SimillarHTTP`, the
   `Inbound` bit reference, the CWE/CWR bit, and the duplicated/suffixed header
   field. The Python V2 preprocessor is recovered; packet/flow extraction is
   not.
2. For a new candidate such as CSE-CIC-IDS2018, its raw PCAPs or exact CSV
   release schema and representative rows, with all 82 inputs produced by the
   same verified feature generation/mapping. Preserve labels and validate the
   benign/attack conversion against actual label values.
3. V2 sample/split identifiers with source row provenance, or a validated
   deterministic reconstruction of the V2 reservoir from the exact training
   CSV and original runtime, to audit exact and tuple/session overlap.

No model or ordered-schema artifact was changed.

## Sources

- [CICFlowMeter README and feature definitions](https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt)
- [Official CSE-CIC-IDS2018 dataset documentation](https://www.unb.ca/cic/datasets/ids-2018.html)
- [Official CIC-DDoS2019 dataset documentation](https://www.unb.ca/cic/datasets/ddos-2019.html)
