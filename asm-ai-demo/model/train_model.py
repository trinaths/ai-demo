import pandas as pd
import joblib
import os
import logging
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.decomposition import PCA
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report

# **🛠 Set up logging**
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# **📂 Paths**
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"

# **📂 Ensure directories exist**
os.makedirs("/data", exist_ok=True)

# **📥 Load dataset**
logger.info("📥 Loading dataset for training...")
df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines='skip')

# **🚨 Ensure dataset is valid**
if df.empty or "prediction" not in df.columns:
    logger.error("❌ Dataset is empty or missing 'prediction' column. Exiting training.")
    exit(1)

# **🔍 Check dataset balance**
normal_count = df[df["prediction"] == 0].shape[0]
malicious_count = df[df["prediction"] == 1].shape[0]

logger.info(f"📊 Dataset: {normal_count} normal vs {malicious_count} malicious.")

if normal_count == 0 or malicious_count == 0:
    logger.error("❌ Not enough data in either class. Exiting.")
    exit(1)

# **🧹 Handle missing values**
df.fillna({"violation": "None", "bot_signature": "Unknown", "ip_reputation": "Good"}, inplace=True)

# **🚨 Feature Engineering**
df["request_size_ratio"] = df["bytes_sent"] / (df["bytes_received"] + 1)  # Avoid division by zero
df["request_rate_norm"] = np.log(df["request_rate"] + 1)  # Normalize request rate

# **🔹 Remove High-Correlation Features (`response_code`)**
df.drop(columns=["response_code"], inplace=True)  # **Prevent Data Leakage**

# **🛠 Use IsolationForest for Anomaly Detection**
iso_forest = IsolationForest(contamination=0.05, random_state=42)
df["anomaly_score"] = iso_forest.fit_predict(df[["bytes_sent", "bytes_received", "request_rate"]])

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🚀 Standardize Features**
scaler = StandardScaler()
features = ["bytes_sent", "bytes_received", "request_rate_norm", "request_size_ratio", "ip_reputation", "bot_signature", "anomaly_score"]
df[features] = scaler.fit_transform(df[features])

# **🚀 Apply PCA (Dimensionality Reduction)**
pca = PCA(n_components=5)
df_pca = pca.fit_transform(df[features])

# **🔄 Balance dataset dynamically if imbalance exists**
min_samples = min(normal_count, malicious_count)
df_normal_balanced = df[df["prediction"] == 0].sample(min_samples, random_state=42)
df_malicious_balanced = df[df["prediction"] == 1].sample(min_samples, random_state=42)

# **Merge balanced dataset**
df_balanced = pd.concat([df_normal_balanced, df_malicious_balanced])

# **🎯 Train-test split**
X_train, X_test, y_train, y_test = train_test_split(
    df_balanced[features], df_balanced["prediction"], test_size=0.2, stratify=df_balanced["prediction"], random_state=42
)

# **🎛 Grid Search for Best Hyperparameters**
param_grid = {
    "n_estimators": [100, 150, 200],
    "max_depth": [5, 7, 10],
    "min_samples_split": [5, 10],
    "min_samples_leaf": [2, 5, 10],
    "class_weight": ["balanced"]
}

rf_model = RandomForestClassifier(random_state=42)

grid_search = GridSearchCV(rf_model, param_grid, cv=3, scoring="accuracy", n_jobs=-1)
grid_search.fit(X_train, y_train)

best_params = grid_search.best_params_
logger.info(f"✅ Best Model Parameters: {best_params}")

# **🚀 Train Optimized Model**
logger.info("🚀 Training optimized model with best parameters...")
model = RandomForestClassifier(**best_params, random_state=42)
model.fit(X_train, y_train)

# **🏆 Compare Against Logistic Regression**
logistic_model = LogisticRegression(max_iter=500)
logistic_model.fit(X_train, y_train)

# **📊 Cross-Validation**
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cross_val_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy")

logger.info(f"📊 Cross-Validation Accuracy Scores: {cross_val_scores}")
logger.info(f"📈 Average CV Accuracy: {cross_val_scores.mean():.4f}")

# **📊 Evaluate model**
y_pred_rf = model.predict(X_test)
y_pred_logistic = logistic_model.predict(X_test)

logger.info("📊 Model Evaluation (RandomForest):")
logger.info("\n%s", classification_report(y_test, y_pred_rf))

logger.info("📊 Model Evaluation (LogisticRegression):")
logger.info("\n%s", classification_report(y_test, y_pred_logistic))

# **💾 Save trained model & encoders**
try:
    joblib.dump(model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Model and encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model: {e}")
    exit(1)