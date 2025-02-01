import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from imblearn.over_sampling import SMOTE
from collections import Counter
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score
import tensorflow as tf
import os
from sklearn.utils import shuffle

# Enable eager execution (in case it's not enabled)
tf.compat.v1.enable_eager_execution()

# Enable Eager Execution for TensorFlow
tf.config.run_functions_eagerly(True)

# Load dataset
csv_filename = "improved_asm_training_data.csv"
data = pd.read_csv(csv_filename)

# Drop unnecessary columns
data = data.drop(columns=["timestamp", "src_ip", "request"])  # Drop non-numeric columns

# Convert categorical features to numeric
data["violation"] = data["violation"].astype("category").cat.codes
data["bot_signature"] = data["bot_signature"].astype("category").cat.codes
data["severity"] = data["severity"].map({"Low": 0, "Medium": 1, "High": 2})
data["user_agent"] = data["user_agent"].astype("category").cat.codes
data["ip_reputation"] = data["ip_reputation"].map({"Good": 0, "Suspicious": 1, "Malicious": 2})

# Handle NaN values using an imputer
imputer = SimpleImputer(strategy="mean")
data.iloc[:, :-1] = imputer.fit_transform(data.iloc[:, :-1])

# Apply log transformation for large-scale values
data["bytes_sent"] = np.log1p(data["bytes_sent"])
data["bytes_received"] = np.log1p(data["bytes_received"])
data["request_rate"] = np.log1p(data["request_rate"])

# Shuffle the dataset before splitting
data = shuffle(data, random_state=42)

#  Ensure Feature Selection Matches Training & Prediction
X = data.drop(columns=["label"]).values  # Keep all relevant features
y = data["label"].values

# Normalize features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Apply SMOTE only if `label=1` is under 20% of dataset
malicious_ratio = np.sum(y) / len(y)
if malicious_ratio < 0.20:
    smote = SMOTE(sampling_strategy=0.2, random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X_scaled, y)
else:
    X_resampled, y_resampled = X_scaled, y

# Use Train-Test Split to Prevent Data Leakage
train_size = int(0.7 * len(X_resampled))
X_train, X_test = X_resampled[:train_size], X_resampled[train_size:]
y_train, y_test = y_resampled[:train_size], y_resampled[train_size:]

print(f"Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

# Introduce Label Noise (10%) to Prevent Memorization
noise_ratio = 0.10
num_noisy_labels = int(len(y_train) * noise_ratio)
noise_indices = np.random.choice(len(y_train), num_noisy_labels, replace=False)
y_train[noise_indices] = 1 - y_train[noise_indices]  # Flip labels randomly

# Add Gaussian Noise to Training Data
def add_noise(X, noise_factor=0.02):
    noise = np.random.normal(loc=0.0, scale=noise_factor, size=X.shape)
    return X + noise

X_train_noisy = add_noise(X_train, noise_factor=0.05)

# Train MLP Model
mlp_model = MLPClassifier(
    hidden_layer_sizes=(32, 16),  # Adjust architecture as necessary
    max_iter=300,
    alpha=0.015,
    learning_rate_init=0.0005,
    solver='adam'
)

# Train MLP Model with Noisy Data
mlp_model.fit(X_train_noisy, y_train)

# Evaluate Model Using Cross-Validation
mlp_cv_score = cross_val_score(mlp_model, X_train_noisy, y_train, cv=5).mean()

# Evaluate on Noisy Test Set
X_noisy_test, y_noisy_test = shuffle(X_test, y_test, random_state=42)
noisy_predictions = mlp_model.predict(X_noisy_test)
noisy_accuracy = accuracy_score(y_noisy_test, noisy_predictions)

# Print Accuracy Metrics
print("\n✅ Model Accuracy Scores:")
print(f"MLP CV Accuracy: {mlp_cv_score:.4f}")
print(f"✅ Noisy Test Set Accuracy: {noisy_accuracy:.4f}")

# Select MLP as the Best Model for Deployment
best_model, best_name = mlp_model, "MLP"

print(f"\n🚀 Deploying Best Model: {best_name}")

# Export Best Model for TensorFlow Serving
export_dir = f"models/anomaly_model_tf/1"
os.makedirs(export_dir, exist_ok=True)

class ModelToTF(tf.Module):
    def __init__(self, model):
        super().__init__()
        self.model = model

    @tf.function(input_signature=[tf.TensorSpec(shape=[None, X_train.shape[1]], dtype=tf.float32)])
    def predict(self, x):
        x = tf.ensure_shape(x, [None, X_train.shape[1]])  # Ensure the input shape matches
        predictions = tf.py_function(self.model.predict, [x], Tout=tf.float32)
        return predictions

# Convert to TensorFlow format for Serving
tf_model = ModelToTF(best_model)
tf.saved_model.save(tf_model, export_dir)

print(f"\nBest Model ({best_name}) successfully exported to TensorFlow format at: {export_dir}")