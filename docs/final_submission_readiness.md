# Final submission readiness

## Findings before archive refresh

- **PASS — saved evaluation evidence:** the four matched-baseline rows and
  frozen V2 reference in the CSVs agree with the report. Recalculation from
  each saved confusion matrix reproduces accuracy, precision, recall, and F1
  exactly. The reported primary Random Forest bootstrap intervals match the
  CSV; all 60 saved intervals contain their corresponding point estimate.
- **PASS — run protocol metadata:** the manifest records 370,605 test rows
  (3,705 BENIGN, 366,900 ATTACK), a 60-second gap, 12,071 past-time tuple
  overlap rows purged, and that the V2 model/schema were not modified. The
  final-year report labels V2 as reference only and does not claim independent
  dataset validation.
- **FAIL — existing ZIP was stale:** its 68 entries and sidecar manifest agreed
  with each other (ZIP SHA-256
  `463A88EE33126C28D98B04826C0BBF885280B0A79928BC6F85D1C8328F7A02E4`), but
  packaged bytes did not match current `application/backend/flow_telemetry.py`
  and `docs/limitation1_independent_evaluation.md`; it also omitted the
  current `docs/final_year_research_evaluation.md`.

## Minimal changes made before rebuilding

- Added saved Random Forest refit confidence intervals to
  `docs/final_year_research_evaluation.md` and clarified that it is the concise
  submission summary; `research/results/report.md` remains the canonical
  detailed output.
- Added the final-year summary to `docs/submission_manifest.md` and the
  explicit allowlist in `research/code/build_submission.py`.
- No model, schema, dataset, or evaluation output was modified. Rebuilding the
  archive refreshes the two stale packaged files from their current working
  copies and includes the new summary.

## Final archive verification

**PASS — refreshed archive:** `IoT-DDoS-IDS-Submission.zip` was rebuilt from
the working copy with 69 allowlisted files. Its SHA-256 is
`A2ECE33A57EAE159B2AC551BDB0C9FE11A5DA49C77F8841310CBD27E4122FA7B`. The
sidecar manifest hash matches; every archive entry matches its manifest and
current working-copy file; there are no missing or extra entries. The archive
contains `docs/final_year_research_evaluation.md` and the current
`application/backend/flow_telemetry.py`.

**PASS — protected artifacts:** model SHA-256 is
`61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2`; ordered
schema SHA-256 is
`C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28`.

No training, evaluation, or project test suite was rerun. Remaining reporting
limitation: the V2 score is not independent-dataset validation, and
capture/session independence for the research-only UDPLag experiment remains
unverified.
