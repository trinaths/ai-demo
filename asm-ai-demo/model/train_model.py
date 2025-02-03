import pandas as pd
import numpy as np
import joblib
import os
import logging
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
from sklearn.linear_model import LogisticRegression

# **🛠 Set up logger**
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# **📍 Paths**
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/model.pkl"
XGB_MODEL_PATH = "/data/xgb_model.pkl"
LOG_MODEL_PATH = "/data/logistic_model.pkl"
SCALER_PATH = "/data/scaler.pkl"
ENCODERS_PATH = "/data/encoders.pkl"

# **📂 Ensure directories exist**
os.makedirs("/data", exist_ok=True)

# **📥 Load dataset**
logger.info("📥 Loading dataset for training...")
try:
    df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines="skip")

    # **🚨 Validate required columns**
    required_columns = [
        "response_code", "bytes_sent", "bytes_received", "request_rate",
        "ip_reputation", "bot_signature", "violation", "prediction"
    ]
    missing_columns = [col for col in required_columns if col not in df.columns]

    if missing_columns:
        raise ValueError(f"❌ Missing columns in dataset: {', '.join(missing_columns)}")

except Exception as e:
    logger.error(f"❌ Error loading dataset: {e}")
    exit(1)

# **🚨 Handle missing values properly**
df.fillna({"violation": "None", "bot_signature": "Unknown", "ip_reputation": "Good"}, inplace=True)

# **🚀 Ensure 'prediction' column is binary**
df["prediction"] = df["prediction"].astype(int)

# **📊 Feature Correlation**
correlation = df.corr()["prediction"].abs().sort_values(ascending=False)
logger.info(f"📊 Feature Correlation:\n{correlation}")

# **🛑 Drop highly correlated features (Above 0.9 correlation)**
high_corr_features = correlation[correlation > 0.9].index.tolist()
high_corr_features.remove("prediction")  # Keep the target variable
logger.info(f"🛑 Dropping highly correlated features: {high_corr_features}")
df.drop(columns=high_corr_features, inplace=True)

# **📊 Balance dataset (Ensure equal normal & malicious samples)**
malicious_df = df[df["prediction"] == 1]
normal_df = df[df["prediction"] == 0]

if len(malicious_df) == 0 or len(normal_df) == 0:
    logger.error("❌ Imbalanced dataset: One class has zero samples.")
    exit(1)

min_size = min(len(malicious_df), len(normal_df))
malicious_df = malicious_df.sample(n=min_size, random_state=42)
normal_df = normal_df.sample(n=min_size, random_state=42)

df = pd.concat([malicious_df, normal_df]).sample(frac=1, random_state=42)  # **Shuffle dataset**

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature", "violation"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **📊 Feature & Target Selection**
features = ["bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
target = "prediction"

X = df[features]
y = df[target]

# **🚨 Validate dataset before splitting**
if X.shape[0] == 0:
    logger.error("❌ No valid samples available for training. Exiting.")
    exit(1)

# **🌟 Normalize Numeric Features**
scaler = StandardScaler()
X[["bytes_sent", "bytes_received", "request_rate"]] = scaler.fit_transform(X[["bytes_sent", "bytes_received", "request_rate"]])

# **🚀 Train/Test Split**
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

logger.info(f"📊 Training on {X_train.shape[0]} samples, Testing on {X_test.shape[0]} samples.")

# **🚀 Train RandomForest Model**
logger.info("🚀 Training RandomForest model...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=5,  # Prevents overfitting
    min_samples_split=10,
    min_samples_leaf=5,
    class_weight="balanced",
    random_state=42
)
rf_model.fit(X_train, y_train)

# **🚀 Train XGBoost Model**
logger.info("🚀 Training XGBoost model...")
xgb_model = XGBClassifier(n_estimators=100, max_depth=3, learning_rate=0.01, random_state=42)
xgb_model.fit(X_train, y_train)

# **🚀 Train Logistic Regression Model**
logger.info("🚀 Training Logistic Regression model...")
log_model = LogisticRegression(class_weight="balanced", max_iter=1000)
log_model.fit(X_train, y_train)

# **📊 Evaluate Models**
y_pred_rf = rf_model.predict(X_test)
y_pred_xgb = xgb_model.predict(X_test)
y_pred_log = log_model.predict(X_test)

logger.info("📊 Model Evaluation (RandomForest):\n" + classification_report(y_test, y_pred_rf))
logger.info("📊 Model Evaluation (XGBoost):\n" + classification_report(y_test, y_pred_xgb))
logger.info("📊 Model Evaluation (LogisticRegression):\n" + classification_report(y_test, y_pred_log))

# **💾 Save Models & Encoders**
try:
    joblib.dump(rf_model, MODEL_PATH)
    joblib.dump(xgb_model, XGB_MODEL_PATH)
    joblib.dump(log_model, LOG_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Models, Scaler, and Encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving models: {e}")
    exit(1)