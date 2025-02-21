#!/usr/bin/env python3
"""
train_model.py

Loads synthetic TS logs, assigns labels, extracts features,
and trains models using:
  - RandomForestClassifier for supervised modules (LTM, APM, SYSTEM, AFM)
  - A simple Q-learning approach for ASM.

The data is split into training and test sets, and both training and test accuracies 
are printed to monitor for overfitting. The trained models are saved into a single file.
"""

import json
import pickle
import logging
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Configure logging.
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

# Define the modules for which we train models.
MODULES = ["LTM", "APM", "ASM", "SYSTEM", "AFM"]

def convert_asm_attack(record):
    """Convert ASM attack signature into a binary indicator."""
    try:
        value = record.get("asmAttackSignatures", "None")
        logging.debug(f"Converting ASM attack signature, value: {value}")
        return 1 if value != "None" else 0
    except Exception as e:
        logging.error(f"Error converting ASM attack: {e}")
        return 0

def assign_label(record):
    """
    Assign a label based on module and usecase.
    
    For LTM and SYSTEM:
      - Usecase 1: 'offload_crypto' if cryptoLoad (or tmmCpu) exceeds threshold.
      - Usecase 4: 'update_routing' if throughputPerformance exceeds threshold.
    For APM:
      - Usecase 2: 'steer_traffic' if connectionsPerformance exceeds threshold.
      - Usecase 3: 'enforce_sla' if connectionsPerformance exceeds threshold.
    For ASM:
      - Usecase 5: 'scale_up' if an attack is detected.
      - Usecase 6: 'discover_service' if an attack signature exists.
      - Usecase 7: 'maintain_cluster' if throughput is low.
    For AFM:
      - Usecase 8: 'block_traffic' if the average threat score is high.
    Otherwise, returns "no_change".
    """
    try:
        module = record["module"]
        usecase = record["usecase"]
        logging.debug(f"Assigning label for module {module}, usecase {usecase}")
        if module in ["LTM", "SYSTEM"]:
            if usecase == 1:
                value = float(record.get("cryptoLoad", 0)) if module == "LTM" else float(record.get("tmmCpu", 0))
                label = "offload_crypto" if value > 0.7 else "no_change"
                logging.debug(f"[{module}] Value: {value} -> Label: {label}")
                return label
            elif usecase == 4:
                tp = float(record.get("throughputPerformance", 0))
                label = "update_routing" if tp > 0.8 else "no_change"
                logging.debug(f"[{module}] Throughput: {tp} -> Label: {label}")
                return label
        elif module == "APM":
            cp = float(record.get("system.connectionsPerformance", 0))
            if usecase == 2:
                label = "steer_traffic" if cp > 0.6 else "no_change"
                logging.debug(f"[APM] Connections Performance: {cp} -> Label: {label}")
                return label
            elif usecase == 3:
                label = "enforce_sla" if cp > 0.8 else "no_change"
                logging.debug(f"[APM] Connections Performance: {cp} -> Label: {label}")
                return label
        elif module == "ASM":
            tp = float(record.get("throughputPerformance", 0))
            attack_indicator = convert_asm_attack(record)
            if usecase == 5:
                label = "scale_up" if attack_indicator == 1 else "no_change"
                logging.debug(f"[ASM] Attack indicator: {attack_indicator} -> Label: {label}")
                return label
            elif usecase == 6:
                label = "discover_service" if record.get("asmAttackSignatures", "None") != "None" else "no_change"
                logging.debug(f"[ASM] Attack signature: {record.get('asmAttackSignatures', 'None')} -> Label: {label}")
                return label
            elif usecase == 7:
                label = "maintain_cluster" if tp < 0.2 else "no_change"
                logging.debug(f"[ASM] Throughput: {tp} -> Label: {label}")
                return label
        elif module == "AFM":
            if usecase == 8:
                afmScore = float(record.get("afmThreatScore", 0))
                accessAnomaly = float(record.get("accessAnomaly", 0))
                asmIndicator = float(record.get("asmAttackIndicator", 0))
                securityIndex = (afmScore + accessAnomaly + asmIndicator) / 3.0
                logging.debug(f"[AFM] SecurityIndex: {securityIndex}")
                return "block_traffic" if securityIndex > 0.7 else "no_change"
    except Exception as e:
        logging.error(f"Error assigning label: {e}")
    return "no_change"

def load_data(log_file):
    """Load logs from the file, assign labels, and group them by module."""
    data = {module: [] for module in MODULES}
    if not os.path.exists(log_file):
        logging.error(f"Log file {log_file} not found.")
        return data
    with open(log_file, "r") as f:
        for line in f:
            try:
                record = json.loads(line)
                record["label"] = assign_label(record)
                module = record.get("module", "LTM")
                data[module].append(record)
            except Exception as e:
                logging.error(f"Error processing line: {e}")
    for module, records in data.items():
        logging.debug(f"Module {module}: Loaded {len(records)} records.")
    return data

def extract_features(module, records):
    """
    Create a DataFrame from records and extract required features.
    Missing fields are filled with 0.
    The returned DataFrame's columns (and their order) should match those used during training.
    """
    df = pd.DataFrame(records)
    logging.debug(f"Initial DataFrame for {module} has shape {df.shape}")
    try:
        if module == "LTM":
            for field in ["cryptoLoad", "throughputPerformance", "latency", "jitter", "packetLoss"]:
                if field not in df.columns:
                    logging.debug(f"Field '{field}' missing in {module}; filling with 0.")
                    df[field] = 0
            features = df[["cryptoLoad", "throughputPerformance", "latency", "jitter", "packetLoss"]]
        elif module == "APM":
            if "system.connectionsPerformance" not in df.columns:
                logging.debug("Field 'system.connectionsPerformance' missing in APM; filling with 0.")
                df["system.connectionsPerformance"] = 0
            features = df[["system.connectionsPerformance"]]
        elif module == "ASM":
            if "throughputPerformance" not in df.columns:
                logging.debug("Field 'throughputPerformance' missing in ASM; filling with 0.")
                df["throughputPerformance"] = 0
            df["attackIndicator"] = df.apply(convert_asm_attack, axis=1)
            features = df[["throughputPerformance", "attackIndicator"]]
        elif module == "SYSTEM":
            for field in ["tmmCpu", "throughputPerformance"]:
                if field not in df.columns:
                    logging.debug(f"Field '{field}' missing in SYSTEM; filling with 0.")
                    df[field] = 0
            features = df[["tmmCpu", "throughputPerformance"]]
        elif module == "AFM":
            if "afmThreatScore" not in df.columns:
                logging.debug("Field 'afmThreatScore' missing in AFM; filling with 0.")
                df["afmThreatScore"] = 0
            features = df[["afmThreatScore"]]
        logging.debug(f"Extracted features for {module} have shape {features.shape}")
        return features
    except Exception as e:
        logging.error(f"Error extracting features for module {module}: {e}")
    return None

def train_supervised(module, records):
    """
    Train a supervised RandomForest model for the given module.
    Splits data into training and test sets, trains the model, and prints training and test accuracies.
    """
    logging.info(f"Training supervised model for {module} with {len(records)} records.")
    X = extract_features(module, records)
    if X is None or X.empty:
        logging.error(f"No features extracted for module {module}.")
        return None
    # Save the feature names for later prediction use.
    feature_names = X.columns.tolist()
    y = pd.DataFrame(records)["label"]
    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        logging.debug(f"{module} - Training set shape: {X_train.shape}; Test set shape: {X_test.shape}")
        clf = RandomForestClassifier(random_state=42, n_estimators=100, max_depth=10, min_samples_split=5)
        clf.fit(X_train, y_train)
        train_acc = clf.score(X_train, y_train)
        test_acc = clf.score(X_test, y_test)
        logging.info(f"[{module}] Training Accuracy: {train_acc:.2f} | Test Accuracy: {test_acc:.2f}")
        # Attach the feature names to the model for later use.
        clf.feature_names = feature_names
        return clf
    except Exception as e:
        logging.error(f"Error training supervised model for {module}: {e}")
        return None

def train_rl(records, alpha=0.1):
    """
    Train a simple Q-learning based RL agent for ASM.
    Uses a Q-table updated with a simple reward mechanism.
    """
    logging.info(f"Training RL agent for ASM with {len(records)} records.")
    actions = ["scale_up", "scale_down", "discover_service", "maintain_cluster", "no_change"]
    q_table = {}
    try:
        for record in records:
            state = (round(float(record.get("throughputPerformance", 0)), 1), convert_asm_attack(record))
            optimal_action = assign_label(record)
            if state not in q_table:
                q_table[state] = {a: 0.0 for a in actions}
            for a in actions:
                reward = 1 if a == optimal_action else 0
                q_table[state][a] += alpha * (reward - q_table[state][a])
        logging.info("[ASM] RL Agent training complete (Q-table updated).")
        logging.debug(f"RL Q-table: {q_table}")
        return q_table
    except Exception as e:
        logging.error(f"Error training RL agent for ASM: {e}")
        return q_table

def train_models(data):
    """
    Train models for each module and return a dictionary mapping module names to trained models.
    """
    models = {}
    for module, records in data.items():
        if not records:
            logging.warning(f"No data for module {module}, skipping training.")
            continue
        if module == "ASM":
            logging.info(f"Training RL agent for module {module} on {len(records)} samples.")
            models[module] = train_rl(records)
        else:
            logging.info(f"Training supervised model for module {module} on {len(records)} samples.")
            models[module] = train_supervised(module, records)
    return models

def main():
    log_file = "synthetic_ts_logs.jsonl"
    logging.info(f"Loading TS log data from {log_file}...")
    data = load_data(log_file)
    logging.info("Training models for each module...")
    models = train_models(data)
    if models:
        model_file = "trained_models.pkl"
        with open(model_file, "wb") as f:
            pickle.dump(models, f)
        logging.info(f"Models saved to {model_file}")
    else:
        logging.error("No models were trained. Check your data.")

if __name__ == "__main__":
    main()