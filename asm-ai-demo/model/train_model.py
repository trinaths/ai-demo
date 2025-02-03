import pandas as pd
import joblib
import os
import logging
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report
from collections import Counter

# **🛠 Set up Logging**
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# **📍 Paths**
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"
SCALER_PATH = "/data/scaler.pkl"

# **📂 Ensure directories exist**
os.makedirs("/data", exist_ok=True)

# **📥 Load dataset**
logger.info("📥 Loading dataset for training...")
df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines="skip")

# **🚨 Validate required columns**
required_columns = [
    "timestamp", "src_ip", "request", "violation", "response_code", "bytes_sent", 
    "bytes_received", "request_rate", "ip_reputation", "bot_signature", "prediction"
]

# **✅ Ensure "severity" column exists**
if "severity" not in df.columns:
    logger.warning("⚠️ 'severity' column missing. Assigning default value: 'Low'.")
    df["severity"] = "Low"

required_columns.append("severity")  # Add severity to required columns

missing_columns = [col for col in required_columns if col not in df.columns]
if missing_columns:
    logger.error(f"❌ Missing columns: {', '.join(missing_columns)}")
    exit(1)

# **🔍 Handle missing values**
df.fillna({"violation": "None", "bot_signature": "Unknown", "ip_reputation": "Good", "severity": "Low"}, inplace=True)
df["prediction"] = df["prediction"].astype(int)

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["violation", "ip_reputation", "bot_signature", "severity"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))  # ✅ Convert categorical values to numbers
    label_encoders[col] = le

# **🛑 Drop non-numeric columns before correlation**
df_numeric = df.drop(columns=["timestamp", "src_ip", "request"])  # ✅ Remove string fields

# **📊 Feature Correlation**
try:
    correlation = df_numeric.corr(numeric_only=True)["prediction"].abs().sort_values(ascending=False)
    logger.info(f"📊 Feature Correlation:\n{correlation}")
    
    # **🛑 Drop Highly Correlated Features (Threshold > 0.95)**
    drop_features = correlation[correlation > 0.95].index.tolist()
    drop_features.remove("prediction")  # Keep prediction
    logger.info(f"🛑 Dropping highly correlated features: {drop_features}")
    df.drop(columns=drop_features, inplace=True)

except Exception as e:
    logger.error(f"❌ Correlation computation failed: {e}")
    exit(1)

# **🛡 Balance dataset using Class Weights**
class_weights = dict(Counter(df["prediction"]))
max_class = max(class_weights.values())
class_weights = {k: max_class / v for k, v in class_weights.items()}

# **📊 Feature & Target Selection**
features = ["bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation", "severity"]

# **✅ Ensure all selected features exist in dataset**
missing_features = [col for col in features if col not in df.columns]
if missing_features:
    logger.error(f"❌ Missing features: {', '.join(missing_features)}")
    exit(1)

X = df[features]
y = df["prediction"]

# **🚀 Standardize Numeric Features**
scaler = StandardScaler()
X[["bytes_sent", "bytes_received", "request_rate"]] = scaler.fit_transform(X[["bytes_sent", "bytes_received", "request_rate"]])

# **🚀 Train/Test Split**
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

logger.info(f"📊 Training on {X_train.shape[0]} samples, Testing on {X_test.shape[0]} samples.")

# **✅ Hyperparameter Tuning for RandomForest**
rf_params = {
    "n_estimators": [100, 150],
    "max_depth": [5, 7, 10],
    "min_samples_split": [5, 20],
    "min_samples_leaf": [2, 5],
}
rf_grid = GridSearchCV(RandomForestClassifier(class_weight=class_weights, random_state=42), rf_params, cv=3)
rf_grid.fit(X_train, y_train)
best_rf = rf_grid.best_estimator_
logger.info(f"✅ Best RandomForest Params: {rf_grid.best_params_}")

# **✅ Train XGBoost Model**
xgb_model = XGBClassifier(use_label_encoder=False, eval_metric="mlogloss", scale_pos_weight=class_weights)
xgb_model.fit(X_train, y_train)

# **✅ Train Ensemble Model**
ensemble_model = VotingClassifier(estimators=[
    ("rf", best_rf),
    ("xgb", xgb_model),
], voting="soft")
ensemble_model.fit(X_train, y_train)

# **📊 Evaluate Model**
y_pred = ensemble_model.predict(X_test)
logger.info("📊 Model Evaluation:\n" + classification_report(y_test, y_pred))

# **💾 Save Model, Scaler & Encoders**
joblib.dump(ensemble_model, MODEL_PATH)
joblib.dump(label_encoders, ENCODERS_PATH)
joblib.dump(scaler, SCALER_PATH)
logger.info("✅ Model, Scaler, and Encoders saved successfully!")