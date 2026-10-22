export async function processCsvUpload(file, postCsv) {
  const preview = await postCsv("/api/dataset/preview", file);
  const analysis = await postCsv("/api/dataset/analyze", file);
  const prediction = await postCsv("/api/predict/csv", file);

  return { preview, analysis, prediction };
}

export function getDashboardStats(trafficAnalysis, modelPrediction) {
  const hasAnalysis = Boolean(trafficAnalysis);
  const stats = [
    {
      key: "totalTraffic",
      title: "Dataset Rows",
      value: hasAnalysis
        ? Number(trafficAnalysis.total_traffic).toLocaleString()
        : "Upload dataset",
      caption: "Rows in the uploaded dataset",
    },
    {
      key: "groundTruthAttacks",
      title: "Ground-Truth Attacks",
      value: hasAnalysis
        ? Number(trafficAnalysis.attacks_detected).toLocaleString()
        : "Upload dataset",
      caption: "Count derived from dataset labels",
    },
    {
      key: "blockingStatus",
      title: "Blocking Status",
      value: "Not Implemented",
      caption: "Automated blocking is not implemented",
    },
    {
      key: "groundTruthAttackTraffic",
      title: "Ground-Truth Attack Traffic",
      value: hasAnalysis
        ? `${trafficAnalysis.total_traffic > 0
            ? (
                (trafficAnalysis.attacks_detected /
                  trafficAnalysis.total_traffic) *
                100
              ).toFixed(1)
            : "0.0"}%`
        : "Upload dataset",
      caption: "Share of rows labeled as attacks",
    },
  ];

  if (modelPrediction) {
    stats.push({
      key: "modelPredictedAttacks",
      title: "Model-Predicted Attacks",
      value: Number(modelPrediction.predicted_attacks).toLocaleString(),
      caption: "Attack predictions for the uploaded dataset",
    });
  }

  return stats;
}
