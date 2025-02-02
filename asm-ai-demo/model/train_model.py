import pandas as pd
import joblib
import os
import logging
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, roc_auc_score

# **🛠 Set up logging**
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# **📂 Paths**
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/best_model.pkl"
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

# **🛑 Drop Highly Correlated Features**
correlation_matrix = df.corr()
high_corr_features = correlation_matrix["prediction"].abs().sort_values(ascending=False)
drop_features = [col for col in high_corr_features.index if col != "prediction" and high_corr_features[col] > 0.95]
if drop_features:
    logger.info(f"🛑 Dropping highly correlated features: {drop_features}")
    df.drop(columns=drop_features, inplace=True)

# **🚀 Feature Selection**
features = [
    "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature"
]
target = "prediction"

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🎯 Train-Test Split**
X_train, X_test, y_train, y_test = train_test_split(df[features], df[target], test_size=0.2, random_state=42, stratify=df[target])

# **🔬 Model Candidates**
models = {
    "RandomForest": RandomForestClassifier(class_weight="balanced", random_state=42),
    "GradientBoosting": GradientBoostingClassifier(random_state=42),
    "XGBoost": XGBClassifier(use_label_encoder=False, eval_metric="logloss", random_state=42),
    "LogisticRegression": LogisticRegression(class_weight="balanced", solver="liblinear", random_state=42)
}

# **🧪 Hyperparameter Tuning**
param_grid = {
    "RandomForest": {
        "n_estimators": [50, 100, 200],
        "max_depth": [3, 5, 7],
        "min_samples_split": [2, 5, 10]
    },
    "GradientBoosting": {
        "n_estimators": [50, 100],
        "learning_rate": [0.01, 0.1],
        "max_depth": [3, 5]
    },
    "XGBoost": {
        "n_estimators": [50, 100],
        "learning_rate": [0.01, 0.1],
        "max_depth": [3, 5]
    },
    "LogisticRegression": {
        "C": [0.01, 0.1, 1]
    }
}

# **🔍 Model Evaluation**
best_model = None
best_auc = 0
best_model_name = ""

for model_name, model in models.items():
    logger.info(f"🚀 Training {model_name}...")
    
    # **Hyperparameter Optimization**
    grid_search = GridSearchCV(model, param_grid[model_name], scoring="roc_auc", cv=5, n_jobs=-1)
    grid_search.fit(X_train, y_train)
    
    best_params = grid_search.best_params_
    logger.info(f"✅ Best {model_name} Parameters: {best_params}")
    
    # **Train with Best Params**
    best_model_instance = model.set_params(**best_params)
    best_model_instance.fit(X_train, y_train)
    
    # **Evaluate Performance**
    y_pred = best_model_instance.predict(X_test)
    auc_score = roc_auc_score(y_test, y_pred)
    
    logger.info(f"📊 Model Evaluation ({model_name}):")
    logger.info("\n%s", classification_report(y_test, y_pred))
    logger.info(f"📊 ROC-AUC Score ({model_name}): {auc_score:.4f}")

    # **Select Best Model**
    if auc_score > best_auc:
        best_auc = auc_score
        best_model = best_model_instance
        best_model_name = model_name

logger.info(f"🏆 Best Selected Model: {best_model_name} with ROC-AUC Score: {best_auc:.4f}")

# **💾 Save Best Model & Encoders**
try:
    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Best Model and encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model: {e}")
    exit(1)