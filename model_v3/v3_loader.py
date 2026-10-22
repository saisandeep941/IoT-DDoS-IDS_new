"""Version-independent V3 loader (no pickle). Needs: numpy, pandas, xgboost."""
import json, os, numpy as np, pandas as pd
from xgboost import XGBClassifier
class V3Model:
    def __init__(self, folder=os.path.dirname(os.path.abspath(__file__))):
        self.meta = json.load(open(os.path.join(folder, "v3_metadata.json")))
        self.features = json.load(open(os.path.join(folder, "v3_features.json")))
        self.medians = np.array(json.load(open(os.path.join(folder, "v3_imputer_medians.json"))), dtype=float)
        self.model = XGBClassifier(); self.model.load_model(os.path.join(folder, "v3_xgb_model.json"))
    def prepare(self, df):
        x = df[self.features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).clip(-1e12, 1e12)
        return x.fillna(pd.Series(self.medians, index=self.features))
    def predict_proba_attack(self, df):
        return self.model.predict_proba(self.prepare(df))[:, 1]
    def predict(self, df, mode="balanced"):
        t = self.meta["operating_points"]["balanced_default" if mode == "balanced" else "strict_low_fpr"]["threshold"]
        p = self.predict_proba_attack(df); return (p >= t).astype(int), p, t
