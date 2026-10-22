# Independent evaluation decision

## Decision

Do not claim that Random Forest V2 has been independently evaluated on a new
dataset. The fastest defensible project path is to use the already completed,
separately refitted research experiment as a **same-source, forward-time,
tuple-purged evaluation**, while reporting the deployed V2 score only as a
non-independent reference. Do not run another evaluation on the same holdout.

## Evidence in the working copy

- The only raw dataset present is
  `application/dataset/01-12/UDPLag.csv` (370,605 rows). The completed run
  `research/results/report.md` and `research/results/run_metadata.json` show it
  was already used as the full test block. Its labels are BENIGN/ATTACK and its
  SHA-256 was recorded during that run.
- The run separately fit a research Random Forest using 10,000 BENIGN and
  10,000 ATTACK rows from earlier source records, excluded a 60-second
  pre-test gap, and purged canonical bidirectional 5-tuple overlaps. It also
  evaluated Extra Trees, Histogram Gradient Boosting, and Logistic Regression.
  This is a distinct research refit, not the frozen V2 model.
- The same test block was used for the deployed V2 reference. The reports
  identify V2's training on later and neighboring periods; its result is not
  an independent or forward-time generalization estimate. The experiment is
  time- and tuple-disjoint within the available CSVs, but capture/session
  independence is unverified because no PCAPs or capture/session IDs are
  available. Consult the existing canonical report; no new metrics are
  calculated here.
- No CSE-CIC-IDS2018 or other fresh dataset is present. Therefore a new
  external common-feature-subset experiment cannot be run now. It is a valid
  *separate model study* in principle: obtain the official labeled CSE-CIC-
  IDS2018 CSVs, define the documented common feature set from those CSVs,
  exclude ambiguous or unavailable fields, and train/evaluate a newly named
  model using a day/file-level holdout. Such results must not be attributed to
  V2 or used as a V2 evaluation.

## V2 reconstruction

The prior artifact comparison records that V2 used seeded class-wise
reservoir sampling (`default_rng(42)`, 100,000 rows per class) followed by a
stratified 80/20 split (`random_state=42`). That algorithm is reproducible for
the exact input byte stream and compatible runtime; a replay carrying source
row identities could enable exact row, feature-vector, flow-key, and tuple
comparisons. The V2 script did not save those identities, indices, an
input-byte checksum, or a runtime manifest. The original processed training
CSV and training script are not in this working copy, so reconstruction was
not performed. Even if staged and replayed, without a training-time checksum
and environment record the result would be a **reconstruction**, not proof of
historical V2 membership. The existing research run's source-file hashes do
not bind the original V2 processed CSV or its V2 sample.

## Exact next action

For the final-year report now, use `docs/research_evaluation.md` and
`research/results/report.md` with the scope above; explicitly state that
independent external evaluation of frozen V2 is unavailable. If an external
dataset result is required, obtain the official CSE-CIC-IDS2018 labeled CSVs,
pre-register a documented common-feature/day-held-out experiment, and label it
as a newly trained research model. Do not use it to fill V2's missing inputs.

The model and ordered feature schema were not modified. Verified working-copy
SHA-256 values:

- Model: `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2`
- Ordered schema: `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28`
