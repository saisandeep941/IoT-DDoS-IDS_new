import axios from "axios";
import { useRef } from "react";
import { useState, useEffect } from "react";

import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

import {
  ShieldCheck, LayoutDashboard, Activity, ShieldAlert,
  Network, Settings, Search, Bell, BrainCircuit,
  CircleCheck, Menu, ArrowUpRight
} from "lucide-react";
import "./App.css";
import LiveCapturePanel from "./LiveCapturePanel.jsx";
import { getDashboardStats, processCsvUpload } from "./uploadWorkflow.js";

const navItems = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Network Traffic", icon: Activity },
  { name: "Threat Detection", icon: ShieldAlert },
  { name: "AI Insights", icon: BrainCircuit },
  { name: "Live Capture", icon: Network },
];

function ConfusionMatrix({ matrix }) {
  return (
    <table className="confusion-matrix" aria-label="Confusion matrix: actual rows, predicted columns">
      <thead><tr><th>Actual / predicted</th><th>Benign</th><th>Attack</th></tr></thead>
      <tbody>
        <tr><th>Benign</th><td>{matrix[0][0].toLocaleString()}</td><td>{matrix[0][1].toLocaleString()}</td></tr>
        <tr><th>Attack</th><td>{matrix[1][0].toLocaleString()}</td><td>{matrix[1][1].toLocaleString()}</td></tr>
      </tbody>
    </table>
  );
}

function App() {

  const [active, setActive] = useState("Overview");
  const [search, setSearch] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const [apiStatus, setApiStatus] = useState("Checking...");
  const [trainingResult, setTrainingResult] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [featureImportance, setFeatureImportance] = useState(null);
  const [detectionHistory, setDetectionHistory] = useState([]);
  const [projectInfo, setProjectInfo] = useState(null);
  const [modelPrediction, setModelPrediction] = useState(null);
  const [shapData, setShapData] = useState(null);
const [shapError, setShapError] = useState("");

const [replayFile, setReplayFile] = useState(null);
const [replayBatchSize, setReplayBatchSize] = useState(25);
const [replayStatus, setReplayStatus] = useState("idle");
const [replayError, setReplayError] = useState("");
const [replayProcessed, setReplayProcessed] = useState(0);
const [replayEvents, setReplayEvents] = useState([]);
const replayInFlight = useRef(false);
const [researchEvaluation, setResearchEvaluation] = useState(null);
const [researchEvaluationError, setResearchEvaluationError] = useState("");

const startReplay = async () => {
  if (!replayFile) return;
  setReplayError("");
  setReplayEvents([]);
  setReplayProcessed(0);
  try {
    const body = new FormData();
    body.append("file", replayFile);
    const response = await axios.post(
      `http://127.0.0.1:8000/api/stream/replay/start?batch_size=${replayBatchSize}`,
      body
    );
    setReplayStatus(response.data.status);
  } catch (error) {
    const detail = error.response?.data?.detail;
    setReplayError(typeof detail === "string" ? detail : JSON.stringify(detail || error.message));
    setReplayStatus("error");
  }
};

const controlReplay = async (action) => {
  setReplayError("");
  try {
    const response = await axios.post(`http://127.0.0.1:8000/api/stream/replay/${action}`);
    setReplayStatus(response.data.status);
    if (action === "clear") {
      setReplayProcessed(0);
      setReplayEvents([]);
      setReplayStatus("idle");
    }
  } catch (error) {
    const detail = error.response?.data?.detail;
    setReplayError(typeof detail === "string" ? detail : JSON.stringify(detail || error.message));
  }
};

useEffect(() => {
  if (replayStatus !== "running") return undefined;
  const timer = setTimeout(async () => {
    if (replayInFlight.current) return;
    replayInFlight.current = true;
    try {
      const response = await axios.post("http://127.0.0.1:8000/api/stream/replay/next");
      setReplayStatus(response.data.status);
      setReplayProcessed(response.data.processed ?? 0);
      if (response.data.events?.length) {
        setReplayEvents((current) => [...response.data.events, ...current].slice(0, 100));
      }
      if (response.data.error) setReplayError(response.data.error);
    } catch (error) {
      const detail = error.response?.data?.detail;
      setReplayError(typeof detail === "string" ? detail : JSON.stringify(detail || error.message));
      setReplayStatus("error");
    } finally {
      replayInFlight.current = false;
    }
  }, 300);
  return () => clearTimeout(timer);
}, [replayStatus, replayProcessed]);



  const [trafficAnalysis, setTrafficAnalysis] = useState(null);

const statIcons = {
  totalTraffic: Network,
  groundTruthAttacks: ShieldAlert,
  blockingStatus: ShieldCheck,
  groundTruthAttackTraffic: Activity,
  modelPredictedAttacks: ShieldAlert,
};
const stats = getDashboardStats(trafficAnalysis, modelPrediction).map((stat) => ({
  ...stat,
  icon: statIcons[stat.key],
}));

const fileInputRef = useRef(null);
const [uploadResult, setUploadResult] = useState(null);
const [uploadError, setUploadError] = useState("");
const [uploading, setUploading] = useState(false);
const [modelStatus, setModelStatus] = useState(null);

useEffect(() => {
  axios
    .get("http://127.0.0.1:8000/api/model/status")
    .then((response) => setModelStatus(response.data))
    .catch((error) => {
      console.error("Model status API error:", error);
      setModelStatus(null);
    });
}, []);





useEffect(() => {
  const fetchData = async () => {
    try {
      const [historyResponse, projectResponse] =
        await Promise.all([
          axios.get("http://127.0.0.1:8000/api/detection-history"),
          axios.get("http://127.0.0.1:8000/api/project/info"),
        ]);

      setDetectionHistory(historyResponse.data.history);
      setProjectInfo(projectResponse.data);
    } catch (error) {
      console.error("Dashboard refresh error:", error);
    }
  };

  fetchData();

  const intervalId = setInterval(fetchData, 5000);

  return () => clearInterval(intervalId);
}, []);


const uploadDataset = async (file) => {
  if (!file) return;

  setUploading(true);
  setUploadError("");
  setUploadResult(null);
  setTrafficAnalysis(null);
  setModelPrediction(null);

  const postCsv = async (endpoint, uploadedFile) => {
    const formData = new FormData();
    formData.append("file", uploadedFile);
    const response = await axios.post(`http://127.0.0.1:8000${endpoint}`, formData);
    return response.data;
  };

  try {
    const { preview, analysis, prediction: predictionResult } =
      await processCsvUpload(file, postCsv);

    setUploadResult(preview);
    setTrafficAnalysis(analysis);
    setModelPrediction(predictionResult);
  } catch (error) {
    const detail = error.response?.data?.detail;
    setUploadError(
      typeof detail === "string"
        ? detail
        : detail?.message || error.message || "Upload failed."
    );
  } finally {
    setUploading(false);
  }
};

useEffect(() => {
  axios.get("http://127.0.0.1:8000/api/health")
    .then((response) => setApiStatus(response.data.status))
    .catch(() => setApiStatus("Disconnected"));
}, []);

  
const filteredAlerts = detectionHistory.filter((alert) =>
  `${alert.prediction} ${alert.risk_score} ${alert.severity} ${alert.source} ${alert.timestamp}`
    .toLowerCase()
    .includes(search.toLowerCase())
);

  const [systemSummary, setSystemSummary] = useState(null);

useEffect(() => {
  axios
    .get("http://127.0.0.1:8000/api/system/summary")
    .then((response) => setSystemSummary(response.data))
    .catch(() => setSystemSummary(null));
}, []);
const [serverTime, setServerTime] = useState(null);

useEffect(() => {
  axios.get("http://127.0.0.1:8000/api/system/time")
    .then((res) => setServerTime(res.data))
    .catch(() => setServerTime(null));
}, []);

useEffect(() => {
  if (active !== "AI Insights") return;

  axios.get("http://127.0.0.1:8000/api/research/evaluation")
    .then((response) => {
      setResearchEvaluation(response.data);
      setResearchEvaluationError("");
    })
    .catch((error) => {
      setResearchEvaluation(null);
      setResearchEvaluationError(
        error.response?.data?.detail || "Saved research evaluation results are unavailable."
      );
    });

  const fetchShapData = async () => {
    try {
      setShapError("");
      const response = await axios.get(
        "http://127.0.0.1:8000/api/model/explain"
      );
      setShapData(response.data);
    } catch {
      setShapError("Failed to load SHAP explanations.");
    }
  };

  fetchShapData();
}, [active]);



  return (
    <div className="app-shell">
      <input
        ref={fileInputRef}
        type="file"
        accept=".csv"
        hidden
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) uploadDataset(file);
          event.target.value = "";
        }}
      />

      <aside className={`sidebar ${menuOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-icon"><ShieldCheck size={25} /></div>
          <div>
            <h2>Sentinel<span>AI</span></h2>
            <p>IoT SECURITY CENTER</p>
          </div>
        </div>

        <div className="nav-label">MAIN MENU</div>
        <nav>
          {navItems.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={`nav-item ${active === name ? "active" : ""}`}
              onClick={() => {
                setActive(name);
                setMenuOpen(false);
              }}
            >
              
<Icon size={19} />
<span>{name}</span>
{name === "Threat Detection" && (
  <span className="nav-count">{detectionHistory.length}</span>
)}

            </button>
          ))}
        </nav>

        <div className="nav-label tools-label">SYSTEM</div>
        <button className="nav-item" onClick={() => setActive("Settings")}>
          <Settings size={19} /><span>Settings</span>
        </button>

        <div className="sidebar-bottom">
          <ShieldCheck size={22} className="green-text" />
          <h4>System Protected</h4>
          <p>Your security dashboard is ready.</p>
          <div className="secure-status"><span /> Interface operational</div>
        </div>

        
<div className="profile">
  <div className="avatar">SA</div>
  <div className="profile-text">
    <strong>Security Admin</strong>
    <span>Administrator</span>
  </div>
  <button
    type="button"
    className="icon-button"
    onClick={() => setActive("Settings")}
    aria-label="Open Settings"
    title="Settings"
  >
    <Settings size={17} />
  </button>
</div>
</aside>


      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu"
              onClick={() => setMenuOpen(!menuOpen)}
            >
              <Menu />
            </button>
            <div>
              <p className="breadcrumb">
                Security Center / <strong>{active}</strong>
              </p>
              <h1>{active}</h1>
            </div>
          </div>
          
<button
  className="icon-button"
  aria-label="Notifications"
  title="Notifications"
  onClick={() => setActive("Threat Detection")}
>
  <Bell size={19} />
</button>

        </header>

        {active === "Live Capture" && <LiveCapturePanel />}

        {active === "Overview" && (
          <>
            <section className="welcome-row">
              <div>
                <h2>Your network, protected.</h2>
                <p>Monitor IoT network activity and security threats.</p>
              </div>
              <div className="date-chip">
                <Activity size={16} /> ML Monitoring Preview
              </div>
            </section>

            <section className="stats-grid">
              {stats.map(({ title, value, caption, icon: Icon }) => (
                <article className="stat-card" key={title}>
                  <div className="stat-top">
                    <div className="stat-icon"><Icon size={20} /></div>
                  </div>
                  <p>{title}</p>
                  <h3>{value}</h3>
                  <span className="stat-caption">{caption}</span>
                </article>
              ))}
            </section>

            <section className="dashboard-grid">
              <article className="panel">
                <h3>Welcome to SentinelAI</h3>
                <p>Intelligent intrusion detection for IoT networks.</p>
                <p>Use the sidebar to explore traffic, threats and AI insights.</p>
              </article>
              
<article className="panel">
  <ShieldCheck size={32} className="green-text" />
  <h3>Detection Status</h3>
  <p>Dashboard interface ready.</p>
  <p>
    ML model integration:{" "}
    {modelStatus?.model_trained === true
      ? "Connected"
      : modelStatus === null
      ? "Checking..."
      : "Unavailable"}
  </p>
  <p>
    Dataset integration:{" "}
    {uploadResult ? "Dataset uploaded" : "No dataset uploaded"}
  </p>
</article>

            </section>
            

{projectInfo && (
  <div className="dashboard-card project-info-card">
    <h3>Project Information</h3>

    <p><strong>Dataset:</strong> {projectInfo.dataset}</p>
    <p><strong>Algorithm:</strong> {projectInfo.algorithm}</p>
    <p><strong>Explainability:</strong> {projectInfo.explainability}</p>
    <p><strong>Frontend:</strong> {projectInfo.frontend}</p>
    <p><strong>Backend:</strong> {projectInfo.backend}</p>
    <p><strong>Status:</strong> {projectInfo.status}</p>
  </div>
)}


            
<div className="panel page-panel">
  <h2>System Summary</h2>
  <p>API: {systemSummary?.api_status ?? "Checking..."}</p>
  <p>Model: {systemSummary?.model_type ?? "Unknown"}</p>
  <p>Dataset: {systemSummary?.dataset ?? "Unknown"}</p>
  <p>Mode: {systemSummary?.mode ?? "Unknown"}</p>
  <p>Server: {serverTime?.status ?? "Checking..."}</p>
  <p>Last checked: {serverTime?.server_time ?? "Loading..."}</p>
  <p>
    Model trained: {systemSummary?.model_trained ? "Yes" : "No"}
  </p>
</div>

            <div className="panel page-panel">
  <h2>Recent Detection History</h2>
  {detectionHistory.map((item) => (
    <div className="detection-details" key={item.id}>
      <div>
        <span>{item.prediction} — {item.severity}</span>
        <strong>{item.risk_score}/100</strong>
      </div>
      <p>{item.source}</p>
    </div>
  ))}
  <p>History shows predictions recorded by the backend.</p>
</div>

            <AlertTable
              alerts={filteredAlerts}
              search={search}
              setSearch={setSearch}
              onView={() => setActive("Threat Detection")}
            />
          </>
        )}

        {active === "Network Traffic" && (
          <section className="panel page-panel">
  <Activity size={32} className="green-text" />
  <h2>Dataset Upload</h2>
  <p>Upload a CSV file to preview network traffic records.</p>

<button
  type="button"
  className="view-all"
  disabled={uploading}
  onClick={() => fileInputRef.current?.click()}
>
  {uploading ? "Uploading..." : "Choose CSV File"}
</button>

  {uploadError && <p>{uploadError}</p>}

  {uploadResult && (
    <>
      <p>File: {uploadResult.filename}</p>
      <p>Rows previewed: {uploadResult.rows_previewed}</p>
      <p>Columns: {uploadResult.columns.join(", ")}</p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {uploadResult.columns.map((column) => (
                <th key={column}>{column}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {uploadResult.preview.map((row, index) => (
              <tr key={index}>
                {uploadResult.columns.map((column) => (
                  <td key={column}>{String(row[column] ?? "")}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>

        {trafficAnalysis && (
          <div className="dashboard-card">
            <h3>Traffic Analysis Results</h3>
            <p>Total Traffic: {trafficAnalysis.total_traffic}</p>
            <p>Ground-Truth Attacks (dataset labels): {trafficAnalysis.attacks_detected}</p>
            <p>Benign Traffic: {trafficAnalysis.benign_traffic}</p>

            <h4>Attack Types (dataset labels)</h4>
            {Object.entries(trafficAnalysis.attack_types).map(
              ([type, count]) => (
                <p key={type}>{type}: {count}</p>
              )
            )}
          </div>
        )}

        {modelPrediction && (
          <div className="dashboard-card">
            <h3>Real ML Model Predictions</h3>
            <p>Model: {modelPrediction.model}</p>
            <p>Total Rows: {modelPrediction.total_rows.toLocaleString()}</p>
            <p>
              Predicted Attacks:{" "}
              {modelPrediction.predicted_attacks.toLocaleString()}
            </p>
            <p>
              Predicted Benign:{" "}
              {modelPrediction.predicted_benign.toLocaleString()}
            </p>

            {modelPrediction.accuracy !== undefined && (
              <>
                <h4>Evaluation Metrics (against dataset labels)</h4>
                <p>Accuracy: {(modelPrediction.accuracy * 100).toFixed(2)}%</p>
                <p>Precision: {(modelPrediction.precision * 100).toFixed(2)}%</p>
                <p>Recall: {(modelPrediction.recall * 100).toFixed(2)}%</p>
                <p>F1 Score: {(modelPrediction.f1_score * 100).toFixed(2)}%</p>
                
{modelPrediction.confusion_matrix && (
  <>
    <h4>Confusion Matrix (dataset labels vs model predictions)</h4>
    <table>
      <thead>
        <tr>
          <th></th>
          <th>Predicted Benign</th>
          <th>Predicted Attack</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <th>Actual Benign</th>
          <td>{modelPrediction.confusion_matrix[0][0].toLocaleString()}</td>
          <td>{modelPrediction.confusion_matrix[0][1].toLocaleString()}</td>
        </tr>
        <tr>
          <th>Actual Attack</th>
          <td>{modelPrediction.confusion_matrix[1][0].toLocaleString()}</td>
          <td>{modelPrediction.confusion_matrix[1][1].toLocaleString()}</td>
        </tr>
      </tbody>
    </table>
  </>
)}

<div className="dashboard-card">
  <h4>Model Evaluation Chart</h4>
  
{modelPrediction.accuracy !== undefined &&
 modelPrediction.precision !== undefined &&
 modelPrediction.recall !== undefined &&
 modelPrediction.f1_score !== undefined ? (
  <ResponsiveContainer width="100%" height={250}>
    <BarChart
      data={[
        { metric: "Accuracy", score: modelPrediction.accuracy * 100 },
        { metric: "Precision", score: modelPrediction.precision * 100 },
        { metric: "Recall", score: modelPrediction.recall * 100 },
        { metric: "F1 Score", score: modelPrediction.f1_score * 100 },
      ]}
    >
      <CartesianGrid strokeDasharray="3 3" />
      <XAxis dataKey="metric" />
      <YAxis domain={[0, 100]} />
      <Tooltip />
      <Bar dataKey="score" fill="#34d399" />
    </BarChart>
  </ResponsiveContainer>
) : (
  <p>
    Evaluation metrics are unavailable. Upload a labeled CSV file
    containing a Label column to evaluate the model.
  </p>
)}

</div>


              </>
            )}
          </div>

        )}
      </div>
    </>
  )}
</section>
        )}

        
{active === "Threat Detection" && (
  <section className="page-panel">
    <h2>Threat Detection</h2>
    <p>Review and search recorded ML predictions.</p>

    
 <div className="dashboard-card csv-stream-controls">
  <h3>CSV Traffic Replay Simulation</h3>
  <p>Replay actual records from a CSV through the frozen Random Forest V2 model. This uses stored traffic, not live packet inference. If a Label column is present, it is shown only as ground truth and never used as a prediction.</p>

 
<div>
  <button
    type="button"
    disabled={!replayFile || replayStatus === "running" || replayStatus === "paused"}
    onClick={startReplay}
  >
    Start replay
  </button>

  <button
    type="button"
    disabled={replayStatus !== "running"}
    onClick={() => controlReplay("pause")}
  >
    Pause
  </button>
  <button type="button" disabled={replayStatus !== "paused"} onClick={() => controlReplay("resume")}>Resume</button>
  <button type="button" disabled={replayStatus !== "running" && replayStatus !== "paused"} onClick={() => controlReplay("stop")}>Stop</button>
  <button type="button" onClick={() => controlReplay("clear")}>Clear replay history</button>
</div>


<div className="csv-stream-controls">
  <h4>Replay source</h4>

  <input
    type="file"
    accept=".csv,text/csv"
    disabled={replayStatus === "running" || replayStatus === "paused"}
    onChange={(event) => {
      setReplayFile(event.target.files?.[0] ?? null);
    }}
  />
  <label>Records per step <input type="number" min="1" max="200" step="1" value={replayBatchSize} disabled={replayStatus === "running" || replayStatus === "paused"} onChange={(event) => setReplayBatchSize(Math.max(1, Math.min(200, Math.trunc(Number(event.target.value) || 1))))} /></label>
</div>

<div className="stream-status">
  <p>Status: <strong>{replayStatus}</strong></p>
  <p>Records processed: <strong>{replayProcessed.toLocaleString()}</strong></p>
</div>

{replayError && <p className="stream-error" role="alert">{replayError}</p>}

  {replayEvents.length > 0 && (
    <div className="stream-result">
      <h4>Latest replay records</h4>
      {replayEvents.slice(0, 10).map((event) => (
        <article key={`${event.replay_session_id}-${event.record_index}`}>
          <strong>Record {event.record_index}: {event.prediction}</strong>
          <span>Risk {event.risk_score}% · {event.severity}</span>
          <span>Processed: {event.timestamp}</span>
          <span>Traffic timestamp: {event.traffic_timestamp || "not provided"}</span>
          {event.ground_truth && <span>Ground truth (offline reference): {event.ground_truth}</span>}
          {event.explanation?.status === "available" ? (
            <span>Top SHAP contributions: {event.explanation.top_features.map((item) => `${item.feature} (${item.impact})`).join(", ")}</span>
          ) : (
            <span>Explanation unavailable: {event.explanation?.reason || "not returned"}</span>
          )}
        </article>
      ))}
    </div>
  )}
</div>


    <AlertTable
      alerts={filteredAlerts}
      search={search}
      setSearch={setSearch}
      onView={() => setActive("AI Insights")}
    />
  </section>
)}


        {active === "AI Insights" && (
          <>
            <section className="welcome-row">
              <div>
                <h2>Understand every prediction.</h2>
                <p>Explore model explanations and threat risk scores.</p>
              </div>
              <div className="date-chip">
                <BrainCircuit size={16} /> AI Workspace
              </div>
            </section>
<section className="stats-grid">
  <article className="stat-card">
    <div className="stat-icon"><BrainCircuit /></div>
    <p>ML Model</p>
    <h3>Random Forest</h3>
    <span className="stat-caption">Real CIC-DDoS2019 model</span>
  </article>

  <article className="stat-card">
    <div className="stat-icon"><ShieldAlert /></div>
    <p>Risk Assessment</p>
    <h3>Prototype</h3>
    <span className="stat-caption">Risk scoring module</span>
  </article>

  <article className="stat-card">
    <div className="stat-icon"><Activity /></div>
    <p>Explainable AI</p>
    <h3>SHAP</h3>
    <span className="stat-caption">Top 15 feature impacts</span>
  </article>

  <article className="stat-card">
    <div className="stat-icon"><CircleCheck /></div>
    <p>Model Evaluation</p>
    <h3>Implemented</h3>
    <span className="stat-caption">CSV evaluation metrics</span>
  </article>
</section>
<section className="panel">
  <div className="panel-header">
    <div>
      <h3>Saved Research Evaluation</h3>
      <p>Verified saved results for {researchEvaluation?.dataset || "the UDPLag test block"}</p>
    </div>
  </div>
  {researchEvaluationError && <p className="error-message" role="alert">{researchEvaluationError}</p>}
  {!researchEvaluation && !researchEvaluationError && <p role="status">Loading saved evaluation results...</p>}
  {researchEvaluation && (
    <>
      <p><strong>Protocol:</strong> {researchEvaluation.evaluation_type}. Positive class: {researchEvaluation.positive_class}; decision threshold: {researchEvaluation.decision_threshold}.</p>
      <p>Test rows: {researchEvaluation.test_rows.toLocaleString()} at natural prevalence — Benign: {researchEvaluation.actual_class_counts.BENIGN.toLocaleString()}, Attack: {researchEvaluation.actual_class_counts.ATTACK.toLocaleString()}.</p>
      <p>Protocol details: {researchEvaluation.protocol.gap_seconds}-second training gap; {researchEvaluation.protocol.training_rows_purged_for_tuple_overlap.toLocaleString()} past-time training rows purged for tuple overlap. Capture/session independence: {researchEvaluation.protocol.capture_session_independence}. Independent-dataset evaluation: {researchEvaluation.protocol.independent_dataset_evaluation}.</p>
      <h4>Matched research-only refits</h4>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Model</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th><th>ROC-AUC</th><th>Average precision</th><th>Confusion matrix</th></tr></thead>
          <tbody>{researchEvaluation.matched_research_refits.map((row) => (
            <tr key={row.model}>
              <th>{row.model}</th>
              {[row.accuracy, row.precision, row.recall, row.f1, row.roc_auc, row.average_precision].map((metric, index) => <td key={index}>{(metric * 100).toFixed(2)}%</td>)}
              <td><details><summary>View matrix</summary><ConfusionMatrix matrix={row.confusion_matrix} /><small>{researchEvaluation.confusion_matrix_layout}</small></details></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <h4>Frozen Random Forest V2 — reference only</h4>
      <p>This is a score on the previously used UDPLag block; it is not an independent evaluation or a matched comparison with the refitted models.</p>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th><th>ROC-AUC</th><th>Average precision</th><th>Confusion matrix</th></tr></thead>
          <tbody><tr>
            {[researchEvaluation.frozen_v2_reference_only.accuracy, researchEvaluation.frozen_v2_reference_only.precision, researchEvaluation.frozen_v2_reference_only.recall, researchEvaluation.frozen_v2_reference_only.f1, researchEvaluation.frozen_v2_reference_only.roc_auc, researchEvaluation.frozen_v2_reference_only.average_precision].map((metric, index) => <td key={index}>{(metric * 100).toFixed(2)}%</td>)}
            <td><details><summary>View matrix</summary><ConfusionMatrix matrix={researchEvaluation.frozen_v2_reference_only.confusion_matrix} /><small>{researchEvaluation.confusion_matrix_layout}</small></details></td>
          </tr></tbody>
        </table>
      </div>
      <details>
        <summary>Saved confidence intervals and model-only efficiency</summary>
        <p>Confidence intervals are the saved row-stratified and tuple-cluster bootstrap intervals; they do not establish capture/session-level uncertainty.</p>
        <div className="table-wrap"><table>
          <thead><tr><th>Model</th><th>Interval type</th><th>Metric</th><th>95% interval</th><th>Replicates</th></tr></thead>
          <tbody>{researchEvaluation.confidence_intervals.map((row, index) => <tr key={`${row.model}-${row.type}-${row.metric}-${index}`}><td>{row.model}</td><td>{row.type}</td><td>{row.metric}</td><td>{(row.lower_95 * 100).toFixed(2)}%–{(row.upper_95 * 100).toFixed(2)}%</td><td>{row.replicates}</td></tr>)}</tbody>
        </table></div>
        <div className="table-wrap"><table>
          <thead><tr><th>Model</th><th>Single-row p50 (ms)</th><th>p95 (ms)</th><th>Full-test batch rows/s</th></tr></thead>
          <tbody>{researchEvaluation.efficiency.map((row) => <tr key={row.model}><th>{row.model}</th><td>{row.single_row_p50_ms.toFixed(3)}</td><td>{row.single_row_p95_ms.toFixed(3)}</td><td>{row.full_test_batch_rows_per_second.toLocaleString(undefined, { maximumFractionDigits: 0 })}</td></tr>)}</tbody>
        </table></div>
        <p>Latency and throughput are model-only measurements; no end-to-end API latency is reported.</p>
      </details>
      <p className="stat-caption">{researchEvaluation.limitations.join(" ")}</p>
    </>
  )}
</section>
<section className="panel">
  <div className="panel-header">
    <div>
      <h3>SHAP Feature Impact</h3>
      <p>Features influencing the model's attack prediction</p>
    </div>
  </div>

  {shapError && <p className="error-message">{shapError}</p>}

  {!shapData && !shapError && <p>Loading SHAP explanations...</p>}

  {shapData && (
    <>
      <p className="stat-caption">
        Model: {shapData.model} | Explained class: {shapData.explained_class}
      </p>

      <div style={{ width: "100%", height: 440 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={shapData?.explanation || []}
            layout="vertical"
            margin={{ top: 10, right: 25, left: 30, bottom: 10 }}
          >
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis type="number" />
            <YAxis
              type="category"
              dataKey="feature"
              width={190}
              tick={{ fontSize: 11 }}
            />
            <Tooltip />
            <Bar
  dataKey="impact"
  name="SHAP impact"
  fill="#38bdf8"
  label={{ position: "right", formatter: (value) => value.toFixed(4) }}
/>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <p className="stat-caption">{shapData.note}</p>
    </>
  )}
</section>

            <section className="panel page-panel">
  <BrainCircuit size={32} className="green-text" />
      <h2>Saved UDPLag Example Explanation</h2>
  <button
  className="view-all"
  onClick={async () => {
    try {
      const response = await axios.get(
        "http://127.0.0.1:8000/api/model/explain"
      );
      setExplanation(response.data);
    } catch (error) {
      alert(error.response?.data?.detail || "Explanation failed.");
    }
  }}
>
  Explain first UDPLag example (SHAP)
</button>
<button
  className="view-all"
  onClick={async () => {
    try {
      const response = await axios.get(
        "http://127.0.0.1:8000/api/model/feature-importance"
      );
      setFeatureImportance(response.data.feature_importance);
    } catch (error) {
      alert(error.response?.data?.detail || "Failed to load feature importance.");
    }
  }}
>
  View Feature Importance
</button>


{featureImportance && featureImportance.slice(0, 15).map((item) => (
  <div className="detection-details" key={item.feature}>
    <div>
      <span>{item.feature}</span>
      <strong>{Number(item.importance).toFixed(6)}</strong>
    </div>
  </div>
))}


{explanation && (
  <div className="detection-details">
    {explanation.explanation.map((item) => (
      <div key={item.feature}>
        <span>{item.feature}</span>
        <strong>{item.impact}</strong>
      </div>
    ))}
    <p>{explanation.note}</p>
  </div>
)}

<p>
  Model status: {modelStatus?.model_trained
    ? "Real Random Forest model available"
    : "Real model not found"}
</p>

<p>
  Trained: {modelStatus?.model_trained ? "Yes" : "No"}
</p>

<p>
  Dataset: {modelStatus?.dataset ?? "Unknown"}
</p>

<button
  type="button"
  className="view-all"
  onClick={() => fileInputRef.current?.click()}
>
  Run ML Prediction
</button>


  <p>
    Model status: Real Random Forest model available.
  </p>
 <button
  className="view-all"
  onClick={async () => {
    try {
      const response = await axios.post(
        "http://127.0.0.1:8000/api/model/train-sample"
      );
      setTrainingResult(response.data);
    } catch (error) {
      alert(error.response?.data?.detail || "Training failed.");
    }
  }}
>
  Train Sample Model
</button>
{trainingResult && (
  <div className="detection-details">
    <div><span>Accuracy</span><strong>{trainingResult.accuracy}%</strong></div>
    <div><span>Precision</span><strong>{trainingResult.precision}%</strong></div>
    <div><span>Recall</span><strong>{trainingResult.recall}%</strong></div>
    <div><span>F1 Score</span><strong>{trainingResult.f1_score}%</strong></div>
    <div>
  <div>
  <span>Confusion Matrix (TN, FP / FN, TP)</span>
  <strong>
    {trainingResult.confusion_matrix
      .map((row) => `[${row.join(", ")}]`)
      .join(" ")}
  </strong>
</div>
  <strong>
    {trainingResult.confusion_matrix
      .map((row) => row.join(" "))
      .join(" | ")}
  </strong>
</div>
    <p>{trainingResult.warning}</p>
  </div>
)}
</section>

          </>
        )}

        {active === "Settings" && (
          <section className="panel page-panel">
            <Settings size={32} className="green-text" />
            <h2>Settings</h2>
            <p>Project configuration</p>
            <div className="detection-details">
              <div><span>Application</span><strong>SentinelAI</strong></div>
              <div><span>Environment</span><strong>Development</strong></div>
              
<div>
  <span>Backend API</span>
  <strong>
    {apiStatus === "healthy" ? "Connected" :
     apiStatus === "Disconnected" ? "Disconnected" : "Checking..."}
  </strong>
</div>
<div>
  <span>Machine learning</span>
  <strong>
    {modelStatus?.model_trained === true
      ? "Connected"
      : modelStatus === null
      ? "Checking..."
      : "Model unavailable"}
  </strong>
</div>

            </div>
          </section>
        )}

        <footer className="footer">
          <span>SentinelAI <b>·</b> IoT Intrusion Detection System</span>
          <span>Demo interface · Live telemetry is observational only</span>
        </footer>
      </main>
    </div>
  );
}

function AlertTable({ alerts, search, setSearch, onView }) {
  return (
    <section className="panel alerts-panel">
      <div className="panel-heading alerts-heading">
        <div>
          <h3>Recent Threat Alerts</h3>
          <p>Real predictions recorded by the ML backend</p>
        </div>

        <div className="alert-tools">
          <div className="search-box">
            <Search size={16} />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search alerts..."
            />
          </div>

          <button className="view-all" onClick={onView}>
            View details <ArrowUpRight size={15} />
          </button>
        </div>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Prediction</th>
              <th>Risk Score</th>
              <th>Severity</th>
              <th>Time</th>
              <th>Source</th>
            </tr>
          </thead>

          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id}>
                <td>{alert.prediction}</td>
                <td>{alert.risk_score}%</td>
                <td>
                  <span
                    className={`severity ${String(
                      alert.severity
                    ).toLowerCase()}`}
                  >
                    {alert.severity}
                  </span>
                </td>
                <td className="muted">
                  {alert.timestamp
                    ? new Date(alert.timestamp).toLocaleString()
                    : "Unknown"}
                </td>
                <td>{alert.source}</td>
              </tr>
            ))}

            {alerts.length === 0 && (
              <tr>
                <td colSpan="5" className="empty-state">
                  No matching detections.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="panel-footer">
        Predictions recorded during the current backend session.
      </div>
    </section>
  );
}

export default App;
