import assert from "node:assert/strict";
import test from "node:test";

import { getDashboardStats, processCsvUpload } from "./uploadWorkflow.js";

test("CSV results are returned only after preview, analysis, and prediction succeed", async () => {
  const file = { name: "sample.csv" };
  const calls = [];
  const responses = {
    "/api/dataset/preview": { filename: file.name },
    "/api/dataset/analyze": { total_traffic: 2, attacks_detected: 1 },
    "/api/predict/csv": { total_rows: 2, predicted_attacks: 0 },
  };

  const result = await processCsvUpload(file, async (endpoint, uploadedFile) => {
    calls.push([endpoint, uploadedFile]);
    return responses[endpoint];
  });

  assert.deepEqual(calls.map(([endpoint]) => endpoint), Object.keys(responses));
  assert.ok(calls.every(([, uploadedFile]) => uploadedFile === file));
  assert.deepEqual(result, {
    preview: responses["/api/dataset/preview"],
    analysis: responses["/api/dataset/analyze"],
    prediction: responses["/api/predict/csv"],
  });
});

test("a prediction failure rejects the upload without publishing staged results", async () => {
  const calls = [];
  const failure = new Error("CSV is missing required model features");

  await assert.rejects(
    processCsvUpload({ name: "invalid.csv" }, async (endpoint) => {
      calls.push(endpoint);
      if (endpoint === "/api/predict/csv") throw failure;
      return { staged: true };
    }),
    failure,
  );

  assert.deepEqual(calls, [
    "/api/dataset/preview",
    "/api/dataset/analyze",
    "/api/predict/csv",
  ]);
});

test("dashboard metrics distinguish label-derived attacks from model predictions", () => {
  const stats = getDashboardStats(
    { total_traffic: 1001, attacks_detected: 500 },
    { predicted_attacks: 0 },
  );

  assert.deepEqual(
    stats.map(({ key, title, value }) => ({ key, title, value })),
    [
      { key: "totalTraffic", title: "Dataset Rows", value: "1,001" },
      {
        key: "groundTruthAttacks",
        title: "Ground-Truth Attacks",
        value: "500",
      },
      {
        key: "blockingStatus",
        title: "Blocking Status",
        value: "Not Implemented",
      },
      {
        key: "groundTruthAttackTraffic",
        title: "Ground-Truth Attack Traffic",
        value: "50.0%",
      },
      {
        key: "modelPredictedAttacks",
        title: "Model-Predicted Attacks",
        value: "0",
      },
    ],
  );
});
