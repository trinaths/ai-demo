# AI Model Using Random Forest and XGBoost
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Load dataset
data = pd.read_csv("asm_training_data.csv")

# Select features (X) and labels (y)
X = data[["request_rate", "bytes_sent", "bytes_received", "violation"]].values
y = data["label"].values  # 1 = Malicious, 0 = Normal

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest Model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# Train XGBoost Model
xgb_model = xgb.XGBClassifier(use_label_encoder=False, eval_metric="logloss")
xgb_model.fit(X_train, y_train)

# Model Evaluation
rf_pred = rf_model.predict(X_test)
xgb_pred = xgb_model.predict(X_test)

print("Random Forest Accuracy:", accuracy_score(y_test, rf_pred))
print("XGBoost Accuracy:", accuracy_score(y_test, xgb_pred))

# Save Best Model
if accuracy_score(y_test, xgb_pred) > accuracy_score(y_test, rf_pred):
    xgb_model.save_model("models/anomaly_model_xgb.json")
    print("XGBoost Model saved!")
else:
    import joblib
    joblib.dump(rf_model, "models/anomaly_model_rf.pkl")
    print("Random Forest Model saved!")