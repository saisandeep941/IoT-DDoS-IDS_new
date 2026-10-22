# Independent evaluation follow-up

**Disposition:** No valid independent evaluation was run. The original V2
training script and input are present, but the extractor lineage does not
resolve all 82 inputs and the available candidate exports do not establish an
exact 82-feature mapping. The existing frozen model and feature schema were
not changed.

## Extractor and priority fields

The CICFlowMeter project source currently documents the standard flow fields.
Its `FlowFeature.java` names `Fwd Header Length` and `CWR Flag Count`; it does
not define `SimillarHTTP`, `Inbound`, `CWE Flag Count`, or
`Fwd Header Length.1`. The source also comments that a different feature
ordinal was deleted as duplicated with the forward-header-length ordinal. That
comment does not establish the provenance or semantics of the extra
`.1`-suffixed column in the V2 CSV. No pinned CICFlowMeter version, build,
configuration, custom extractor source, or PCAP-to-CSV generation record was
found in the original project artifacts inspected for the earlier report.

| V2 feature | What the available evidence establishes | Still unknown |
|---|---|---|
| `SimillarHTTP` | Present in the CIC-DDoS2019-derived training CSV. The V2 script coerces numeric-looking values and maps nonnumeric strings to missing; the fitted pipeline median-imputes missing values. Inspected rows include URL-like text and `0`. | What the field represents, how values are assigned, whether it is a CICFlowMeter extension or later dataset transformation, and the intended representation for new flows. |
| `Inbound` | Present as integer 0/1 in inspected training rows and passed through numeric coercion. | Which network boundary or endpoint defines “inbound,” and the exact assignment rule. Current upstream CICFlowMeter `FlowFeature.java` does not define it. |
| `CWE Flag Count` | Present as integer 0/1 in inspected rows. The current upstream source names `CWR Flag Count`, not CWE. | Whether V2’s field counts CWR or CWE packets, whether the name is a transcription error, and the exact counting implementation. |
| `Fwd Header Length.1` | Present as a second model input. It equals `Fwd Header Length` in inspected records; the original training script treats it as an independent numeric input. | Whether it is a duplicated source column, how it was produced, whether equality holds throughout the full source, and why inspected values include negatives. The current upstream source only establishes the ordinary `Fwd Header Length` field. |

The Python training pipeline defines numeric coercion, infinity-to-missing
conversion, removal of all-missing sampled columns, and median imputation. It
does not define packet-to-flow calculations for these fields. No authoritative
definition justifies substituting values for the two custom inputs or
collapsing the suffixed duplicate.

## Candidate dataset and feature compatibility

The closest documented external candidate found is **CSE-CIC-IDS2018**. The
official dataset page describes captures and event logs from the testbed,
features extracted with CICFlowMeter-V3, attack scenarios, labeling using the
scenario schedule plus source/destination IPs, ports, and protocol, and
redistribution subject to citation. It describes an 80-feature export, not
the protected V2 82-feature schema. Its published documentation does not
establish compatible values for `SimillarHTTP`, `Inbound`, or
`Fwd Header Length.1`, nor resolve the CWE/CWR discrepancy. Thus it is a
legitimate candidate source, but **not a usable input table for this frozen
model on the evidence available**. No local CSE-CIC-IDS2018 data was found in
the prior project inventory. The CIC-DDoS2019-derived `UDPLag.csv` has the
matching source family/schema but was already used for evaluation and is not
a new independent candidate.

To reconsider CSE-CIC-IDS2018, the needed inputs are its raw PCAPs or official
CSV release plus the exact V2-compatible feature-generation implementation
and configuration, including proven generation of every protected input.
Using the official V3 extractor alone would not supply evidence for the
custom/missing fields. Dataset labels must also be retained and mapped under
the official flow-labeling method; no new label conversion or metrics were
performed here.

## V2 sample reconstruction and separation

The original V2 script records enough algorithmic settings to reproduce its
sampling procedure against the present `processed_without_udplag.csv`: 50,000
row chunks, per-class reservoir cap of 100,000, `numpy.random.default_rng(42)`,
then stratified `train_test_split(test_size=0.2, random_state=42)`. The current
input and script are available. A replay that carries source-file/row identity
alongside each feature row could produce candidate V2 reservoir and split
membership without fitting or saving a model.

That would enable exact input-row and feature-vector comparisons, as well as
flow-key/tuple and timestamp comparisons where the candidate preserves those
identifiers. It would not prove packet/session identity where identifiers are
missing or transformed, nor establish that present-day rows were generated
from the same source PCAPs.

The script saves no selected row IDs, split indices, input checksum, or
runtime/package manifest. Therefore a replay is deterministic for a fixed
input byte stream and compatible NumPy/scikit-learn runtime, but the historical
training membership cannot be certified from the model alone: there is no
training-time input hash or environment record tying this file and runtime to
the run that produced the protected model. In addition, the script drops
source identity before reservoir sampling; a provenance-aware replay would
need to carry those IDs in parallel while preserving the exact row stream and
sampling decisions. No such full replay was run, and no training or model
write was performed.

The source-level exclusion of `UDPLag.csv` from the merged V2 input supports
file-level separation for that file, but it does not resolve cross-file flow
or tuple overlap, and UDPLag has already been used as evaluation data.

## Exact blockers and next action

1. Obtain the exact CICFlowMeter/custom extractor source revision, build and
   configuration used to produce the CIC-DDoS2019-derived CSVs, with code or
   authoritative documentation defining `SimillarHTTP`, `Inbound`, CWE/CWR,
   and the second forward-header column.
2. Obtain a candidate independent dataset’s raw captures or full CSV schema
   and labels, then demonstrate exact generation and ordered mapping of all
   82 model inputs using that recovered extractor. CSE-CIC-IDS2018 is the
   closest documented candidate, but its documented V3 export alone is not
   compatible evidence.
3. Obtain a training-time checksum and runtime manifest, or a V2 selected-row
   and split manifest with source provenance. If unavailable, replay the
   reservoir/split on the exact archived input while carrying source row IDs,
   record the environment and input hash, and label the result a
   reconstruction rather than proven historical membership. Compare the
   reconstructed training membership against candidate IDs/flow keys before
   any evaluation.

Until items 1–3 are resolved, the frozen model must not receive guessed,
imputed-from-another-dataset, or silently omitted fields for external
evaluation. No independent metrics are reported.

## References

- [CICFlowMeter upstream `FlowFeature.java`](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java)
- [Official CSE-CIC-IDS2018 documentation](https://www.unb.ca/cic/datasets/ids-2018.html)
- [Original V2 artifact and training-pipeline comparison](original_v2_training_artifact_comparison.md)
- [Ordered V2 feature compatibility review](rf_v2_feature_compatibility.md)
