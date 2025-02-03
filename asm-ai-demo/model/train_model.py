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
    "bytes_sent", "bytes_received", "request_rate",
    "ip_reputation", "bot_signature", "violation"
]
missing_columns = [col for col in required_columns if col not in df.columns]
if missing_columns:
    logger.error(f"❌ Missing columns: {', '.join(missing_columns)}")
    exit(1)

# **🚨 Handle missing values properly**
df.fillna({"violation": "None", "bot_signature": "Unknown", "ip_reputation": "Good"}, inplace=True)

# **🚀 Encode Target Variable (`ip_reputation`)**
label_encoders = {"ip_reputation": LabelEncoder()}
df["ip_reputation"] = label_encoders["ip_reputation"].fit_transform(df["ip_reputation"].astype(str))

# **📊 Feature Selection**
features = ["bytes_sent", "bytes_received", "request_rate", "bot_signature", "violation"]
target = "ip_reputation"

# **🔹 Encode categorical variables**
for col in ["bot_signature", "violation"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🚀 Balance dataset across `ip_reputation` categories**
df_balanced = df.groupby("ip_reputation").apply(lambda x: x.sample(n=min(len(x), 2000), random_state=42))
df_balanced = df_balanced.reset_index(drop=True)

# **✅ Apply Feature Scaling**
scaler = StandardScaler()
df_balanced[["bytes_sent", "bytes_received", "request_rate"]] = scaler.fit_transform(
    df_balanced[["bytes_sent", "bytes_received", "request_rate"]]
)

# **🚀 Train/Test Split**
X = df_balanced[features]
y = df_balanced[target]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

logger.info(f"📊 Training on {X_train.shape[0]} samples, Testing on {X_test.shape[0]} samples.")

# **🚀 Hyperparameter Tuning for RandomForest**
rf_model = RandomForestClassifier(class_weight="balanced", random_state=42)
rf_params = {
    "n_estimators": [100, 150],
    "max_depth": [7, 12],
    "min_samples_split": [10, 20],
    "min_samples_leaf": [5, 10]
}
rf_grid = GridSearchCV(rf_model, rf_params, cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42), scoring="accuracy", n_jobs=-1)
rf_grid.fit(X_train, y_train)
rf_best = rf_grid.best_estimator_

logger.info(f"✅ Best RandomForest Params: {rf_grid.best_params_}")

# **🚀 Train XGBoost Model (Regularized)**
xgb_model = XGBClassifier(
    use_label_encoder=False, eval_metric="logloss",
    max_depth=6, min_child_weight=4, gamma=0.1, learning_rate=0.05
)
xgb_model.fit(X_train, y_train)

# **🚀 Train Logistic Regression (ElasticNet Regularization)**
log_reg = LogisticRegression(
    C=0.1, class_weight="balanced", max_iter=500, solver="saga", penalty="elasticnet", l1_ratio=0.5
)
log_reg.fit(X_train, y_train)

# **📊 Evaluate All Models**
logger.info("📊 Model Evaluation (RandomForest):\n" + classification_report(y_test, rf_best.predict(X_test)))
logger.info("📊 Model Evaluation (XGBoost):\n" + classification_report(y_test, xgb_model.predict(X_test)))
logger.info("📊 Model Evaluation (LogisticRegression):\n" + classification_report(y_test, log_reg.predict(X_test)))

# **💾 Save Models & Encoders**
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