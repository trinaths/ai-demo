import pandas as pd
import joblib
import os
import logging
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.utils import shuffle
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb

# **🛠 Set up logging**
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# **📂 Paths**
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_RF_PATH = "/data/model_rf.pkl"
MODEL_XGB_PATH = "/data/model_xgb.pkl"
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

# **🚀 Exclude non-numeric columns for correlation**
numeric_features = df.select_dtypes(include=["number"])  
correlation_matrix = numeric_features.corr()

# **📊 Drop Highly Correlated Features**
highly_correlated_features = ["response_code"]
logger.info(f"🛑 Dropping highly correlated features: {highly_correlated_features}")
df.drop(columns=highly_correlated_features, inplace=True, errors="ignore")

# **🔹 Feature Selection**
features = ["bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature"]
target = "prediction"

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🚀 Shuffle dataset**
df = shuffle(df, random_state=42)

# **🎯 Train-Test Split**
X = df[features]
y = df[target]

# **💡 Create a validation set before final testing**
X_train, X_valid, y_train, y_valid = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# **🚀 Train Optimized RandomForest Model**
logger.info("🚀 Training optimized RandomForest model...")
rf_model = RandomForestClassifier(
    n_estimators=150,  
    max_depth=7,  # **Lower depth prevents overfitting**
    min_samples_split=10,  
    min_samples_leaf=5,  
    max_features="sqrt",  # **Random feature selection for better generalization**
    class_weight="balanced",  
    random_state=42
)
rf_model.fit(X_train, y_train)

# **🚀 Train Optimized XGBoost Model**
logger.info("🚀 Training optimized XGBoost model...")
xgb_model = xgb.XGBClassifier(
    learning_rate=0.01,
    max_depth=3,
    n_estimators=100,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42
)
xgb_model.fit(X_train, y_train)

# **📊 Evaluate Models**
y_pred_rf = rf_model.predict(X_valid)
y_pred_xgb = xgb_model.predict(X_valid)

logger.info("📊 Model Evaluation (RandomForest):")
logger.info("\n%s", classification_report(y_valid, y_pred_rf))
logger.info(f"📊 ROC-AUC Score (RandomForest): {roc_auc_score(y_valid, y_pred_rf):.4f}")

logger.info("📊 Model Evaluation (XGBoost):")
logger.info("\n%s", classification_report(y_valid, y_pred_xgb))
logger.info(f"📊 ROC-AUC Score (XGBoost): {roc_auc_score(y_valid, y_pred_xgb):.4f}")

# **💾 Save trained models & encoders**
try:
    joblib.dump(rf_model, MODEL_RF_PATH)
    joblib.dump(xgb_model, MODEL_XGB_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Models and encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model: {e}")
    exit(1)