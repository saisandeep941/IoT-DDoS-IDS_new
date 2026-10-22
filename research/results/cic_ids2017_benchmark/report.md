# CIC-IDS2017 independent benchmark (research-only)

This experiment trains new models on CIC-IDS2017. It is not an evaluation of the frozen Random Forest V2 model.

- Training files: Monday-WorkingHours.pcap_ISCX.csv, Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv, Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv, Tuesday-WorkingHours.pcap_ISCX.csv, Wednesday-workingHours.pcap_ISCX.csv
- Held-out test files: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv, Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv, Friday-WorkingHours-Morning.pcap_ISCX.csv
- Training sample: 20000 rows (10000 benign, 10000 attack); cap 10,000 per class.
- Full held-out Friday rows evaluated: 703,245 (benign 414,322, attack 288,923).
- Features: 78 CIC-IDS2017 columns shared with the V2 schema, selected in V2 schema order; no missing V2 fields were synthesized.
- Binary labels: BENIGN=0; every nonblank attack label=1. The displayed raw class labels remain available in run metadata.
- Preprocessing: invalid numeric text and infinities become missing; median imputation is fitted within each model pipeline on training rows only. Logistic Regression also scales using training rows only.
- Test data is streamed in chunks and never sampled or used in preprocessing/model selection.
- Metrics use `estimator.predict`; precision, recall, and F1 treat attack (1) as positive.
- Limitations: one held-out collection day; capture/session independence is not asserted; release-copy checksums authenticate these local files only, not their download source.

## Results

| Model | Accuracy | Attack precision | Attack recall | Attack F1 | TN | FP | FN | TP | Fit s | Test inference s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| dummy_majority | 0.589157 | 0.000000 | 0.000000 | 0.000000 | 414322 | 0 | 288923 | 0 | 0.164 | 0.465 |
| logistic_regression | 0.729446 | 0.871699 | 0.400397 | 0.548741 | 397295 | 17027 | 173239 | 115684 | 0.599 | 0.767 |
| random_forest | 0.703762 | 0.988757 | 0.282158 | 0.439031 | 413395 | 927 | 207401 | 81522 | 0.466 | 1.751 |
| extra_trees | 0.698522 | 0.986834 | 0.269795 | 0.423741 | 413282 | 1040 | 210973 | 77950 | 0.378 | 1.963 |
