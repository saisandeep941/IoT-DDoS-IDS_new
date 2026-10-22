# Prospective provenance protocol

This protocol is for future runs. It does not reconstruct or certify the historical Random Forest V2 run. The current V2 artifact's historical input bytes, extractor, and selected row membership are not linked by available run records.

## Before processing

1. Create a new run directory; keep source data read-only. Record dataset name/release, publisher, source or archive location, license, acquisition date, and label documentation.
2. Hash every raw input file before processing. Record exact file order, sizes, and hashes. Preserve source names and generation timestamps.
3. Record the flow-feature generator source revision or binary/build hash, configuration hash, exact invocation, wrappers, post-export code hashes, runtime versions, and references defining every field. Record raw and exported file hashes and their mapping.
4. Save the exact ordered feature list and its hash. For each field record type, units, definition, generation rule, and missing-value behavior. Reject unresolved mappings rather than substituting similarly named values.

## During training

1. Record the trainer source hash, dependency/runtime versions, model configuration, preprocessing, seeds, and deterministic sampling algorithm/parameters.
2. Before dropping identifiers, assign stable source-row identities (for example, source-file SHA-256 plus original data-row ordinal). Save selected sample identities and train/validation/test membership as separate immutable artifacts and record their hashes. Use protected opaque identifiers for sensitive flow/session values; do not publish raw addresses.
3. Record all preprocessing fit boundaries. Fit imputers, scalers, feature selection, and thresholds using training data only. Preserve the model output hash after successful serialization; do not overwrite unrelated frozen artifacts.
4. Write the completed manifest only after inputs, splits, and outputs have been hashed. Keep the manifest with the artifacts and record its own final hash in a separate completion record or signed release metadata to avoid a self-hash cycle.

## Before independent evaluation

1. Establish dataset provenance, license, label semantics, row validity, exact ordered feature compatibility, units, extractor parity, and preprocessing parity. Record checks and evidence paths/hashes.
2. Compare evaluation row identities with saved training/validation identities. Where flow/session independence is claimed, compare documented flow/session keys as well; state hash/identifier limitations and report the actual overlap-check scope.
3. Use the frozen model read-only. Do not retrain, tune thresholds, or fit preprocessing on evaluation data. Save predictions, metrics, confusion matrix, class counts, inference timing, script hash, and command/configuration.
4. Label results by dataset and evaluation design. If any compatibility or separation prerequisite is unresolved, stop without reporting independent-evaluation metrics.

## Status vocabulary

Mark each evidence item `verified`, `partially_supported`, or `unresolved`, and cite the artifact path and hash or source location. Distinguish source-code configuration from evidence that a particular historical run executed it. A replay without a contemporaneous run anchor is a `reconstruction`, never proof of historical membership. Never retrofit this protocol's template into a synthetic record for the old V2 run.
