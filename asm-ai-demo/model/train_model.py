import pandas as pd
import joblib
import os
import logging
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, roc_auc_score

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

# **🚨 Drop Features with High Correlation Dynamically**
correlation_threshold = 0.90
# 🚀 Exclude non-numeric columns before correlation
numeric_features = df.select_dtypes(include=["number"])  # Only numeric columns
correlation_matrix = numeric_features.corr()

# 🔍 Log feature correlation with 'prediction'
logger.info("📊 Feature Correlation with 'prediction':\n%s", correlation_matrix["prediction"].abs().sort_values(ascending=False))
high_corr_features = correlation_matrix["prediction"].abs().sort_values(ascending=False)
features_to_drop = high_corr_features[high_corr_features > correlation_threshold].index.tolist()

if "prediction" in features_to_drop:
    features_to_drop.remove("prediction")

df.drop(columns=features_to_drop, inplace=True, errors="ignore")
logger.info(f"🛑 Dropping highly correlated features: {features_to_drop}")

# **🚀 Feature Engineering**
df["request_size_ratio"] = df["bytes_sent"] / (df["bytes_received"] + 1)  # Avoid division by zero
df["request_rate_norm"] = np.log(df["request_rate"] + 1)  # Normalize request rate

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🚀 Standardize Features**
scaler = StandardScaler()
features = ["bytes_sent", "bytes_received", "request_rate_norm", "request_size_ratio", "ip_reputation", "bot_signature"]
df[features] = scaler.fit_transform(df[features])

# **🔄 Balance dataset dynamically if imbalance exists**
min_samples = min(normal_count, malicious_count)
df_normal_balanced = df[df["prediction"] == 0].sample(min_samples, random_state=42)
df_malicious_balanced = df[df["prediction"] == 1].sample(min_samples, random_state=42)

# **Merge balanced dataset**
df_balanced = pd.concat([df_normal_balanced, df_malicious_balanced])

# **🎯 Train-test split**
X_train, X_test, y_train, y_test = train_test_split(
    df_balanced[features], df_balanced["prediction"], test_size=0.3, stratify=df_balanced["prediction"], random_state=42
)

# **🎛 Hyperparameter Search for XGBoost**
xgb_model = XGBClassifier(
    n_estimators=200,
    max_depth=5,
    learning_rate=0.05,
    eval_metric="logloss",
    use_label_encoder=False
)

grid_search = GridSearchCV(
    xgb_model,
    param_grid={
        "max_depth": [3, 5, 7],
        "learning_rate": [0.01, 0.05, 0.1],
        "n_estimators": [100, 200, 300]
    },
    cv=3,
    scoring="roc_auc",
    n_jobs=-1
)

grid_search.fit(X_train, y_train)
best_xgb = grid_search.best_estimator_
logger.info(f"✅ Best XGBoost Parameters: {grid_search.best_params_}")

# **🚀 Train Optimized Model**
logger.info("🚀 Training optimized RandomForest model...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=5,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42
)
rf_model.fit(X_train, y_train)

# **📊 Evaluate model**
y_pred_rf = rf_model.predict(X_test)
y_pred_xgb = best_xgb.predict(X_test)

logger.info("📊 Model Evaluation (RandomForest):")
logger.info("\n%s", classification_report(y_test, y_pred_rf))
logger.info("📊 ROC-AUC Score (RandomForest): %.4f" % roc_auc_score(y_test, rf_model.predict_proba(X_test)[:, 1]))

logger.info("📊 Model Evaluation (XGBoost):")
logger.info("\n%s", classification_report(y_test, y_pred_xgb))
logger.info("📊 ROC-AUC Score (XGBoost): %.4f" % roc_auc_score(y_test, best_xgb.predict_proba(X_test)[:, 1]))

# **💾 Save trained models & encoders**
try:
    joblib.dump(best_xgb, "/data/xgb_model.pkl")
    joblib.dump(rf_model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Models and encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model: {e}")
    exit(1)