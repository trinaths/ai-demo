import pandas as pd
import joblib
import os
import logging
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.metrics import classification_report

# **🛠 Set up logger**
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# **📍 Paths**
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/model.pkl"
XGB_MODEL_PATH = "/data/xgb_model.pkl"
LOG_REG_MODEL_PATH = "/data/log_reg_model.pkl"
SCALER_PATH = "/data/scaler.pkl"
ENCODERS_PATH = "/data/encoders.pkl"

# **📂 Ensure directories exist**
os.makedirs("/data", exist_ok=True)

# **📥 Load dataset**
logger.info("📥 Loading dataset for training...")
df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines="skip")

# **🚨 Validate required columns**
required_columns = [
    "response_code", "bytes_sent", "bytes_received", "request_rate",
    "ip_reputation", "bot_signature", "violation", "prediction"
]
missing_columns = [col for col in required_columns if col not in df.columns]
if missing_columns:
    logger.error(f"❌ Missing columns: {', '.join(missing_columns)}")
    exit(1)

# **🚨 Handle missing values properly**
df.fillna({"violation": "None", "bot_signature": "Unknown", "ip_reputation": "Good"}, inplace=True)

# **🚀 Ensure 'prediction' column is binary**
df["prediction"] = df["prediction"].astype(int)

# **📊 Feature Selection**
features = ["bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
target = "prediction"

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature", "violation"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🚀 Balance dataset (Prevent Overfitting)**
malicious_df = df[df["prediction"] == 1]
normal_df = df[df["prediction"] == 0]

if len(malicious_df) == 0 or len(normal_df) == 0:
    logger.error("❌ Imbalanced dataset: One class has zero samples.")
    exit(1)

min_size = min(len(malicious_df), len(normal_df))
malicious_df = malicious_df.sample(n=min_size, random_state=42)
normal_df = normal_df.sample(n=min_size, random_state=42)

df = pd.concat([malicious_df, normal_df]).sample(frac=1, random_state=42)  # **Shuffle dataset**

# **🚀 Train/Test Split**
X = df[features]
y = df[target]

# **✅ Apply Feature Scaling (Fix SettingWithCopyWarning)**
scaler = StandardScaler()
X.loc[:, ["bytes_sent", "bytes_received", "request_rate"]] = scaler.fit_transform(
    X[["bytes_sent", "bytes_received", "request_rate"]]
)

# **🚀 Split into Training & Testing Sets**
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

logger.info(f"📊 Training on {X_train.shape[0]} samples, Testing on {X_test.shape[0]} samples.")

# **✅ Apply K-Fold Cross Validation**
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# **🚀 Hyperparameter Tuning for RandomForest**
rf_model = RandomForestClassifier(class_weight="balanced", random_state=42)
rf_params = {
    "n_estimators": [100, 150],
    "max_depth": [5, 10],
    "min_samples_split": [5, 10],
    "min_samples_leaf": [2, 5],
}
rf_grid = GridSearchCV(rf_model, rf_params, cv=cv, scoring="accuracy", n_jobs=-1)
rf_grid.fit(X_train, y_train)
rf_best = rf_grid.best_estimator_

logger.info(f"✅ Best RandomForest Params: {rf_grid.best_params_}")

# **🚀 Train XGBoost Model**
xgb_model = XGBClassifier(use_label_encoder=False, eval_metric="logloss", scale_pos_weight=len(normal_df) / len(malicious_df))
xgb_model.fit(X_train, y_train)

# **🚀 Train Logistic Regression (Regularized)**
log_reg = LogisticRegression(C=0.5, class_weight="balanced", max_iter=500, solver="lbfgs")
log_reg.fit(X_train, y_train)

# **📊 Evaluate All Models**
logger.info("📊 Model Evaluation (RandomForest):\n" + classification_report(y_test, rf_best.predict(X_test)))
logger.info("📊 Model Evaluation (XGBoost):\n" + classification_report(y_test, xgb_model.predict(X_test)))
logger.info("📊 Model Evaluation (LogisticRegression):\n" + classification_report(y_test, log_reg.predict(X_test)))

# **💾 Save Best Model, Scaler & Encoders**
try:
    joblib.dump(rf_best, MODEL_PATH)
    joblib.dump(xgb_model, XGB_MODEL_PATH)
    joblib.dump(log_reg, LOG_REG_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Models, Scaler, and Encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model: {e}")
    exit(1)