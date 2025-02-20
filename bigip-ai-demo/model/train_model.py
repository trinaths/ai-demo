#!/usr/bin/env python3
"""
train_model.py

Loads synthetic TS logs, assigns labels based on usecase thresholds,
extracts features, trains supervised models (RandomForest for LTM, APM, SYSTEM, AFM)
and an RL agent (Q-learning for ASM), and saves the models.
"""
import json
import pickle
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

modules = ["LTM", "APM", "ASM", "SYSTEM", "AFM"]

def convert_asm_attack(record):
    return 1 if record.get("asmAttackSignatures", "None") != "None" else 0

def assign_label(record):
    module = record["module"]
    usecase = record["usecase"]
    if module in ["LTM", "SYSTEM"]:
        if usecase == 1:
            value = record.get("cryptoLoad", 0) if module == "LTM" else record.get("tmmCpu", 0)
            return "offload_crypto" if value > 0.7 else "no_change"
        elif usecase == 4:
            tp = record.get("throughputPerformance", 0)
            return "update_routing" if tp > 0.8 else "no_change"
    elif module == "APM":
        cp = record.get("system.connectionsPerformance", 0)
        if usecase == 2:
            return "steer_traffic" if cp > 0.6 else "no_change"
        elif usecase == 3:
            return "enforce_sla" if cp > 0.8 else "no_change"
    elif module == "ASM":
        tp = record.get("throughputPerformance", 0)
        attack_indicator = convert_asm_attack(record)
        if usecase == 5:
            return "scale_up" if attack_indicator == 1 else "no_change"
        elif usecase == 6:
            return "discover_service" if record.get("asmAttackSignatures", "None") != "None" else "no_change"
        elif usecase == 7:
            return "maintain_cluster" if tp < 0.2 else "no_change"
    elif module == "AFM":
        if usecase == 8:
            afmScore = record.get("afmThreatScore", 0)
            accessAnomaly = record.get("accessAnomaly", 0)
            asmIndicator = record.get("asmAttackIndicator", 0)
            securityIndex = (afmScore + accessAnomaly + asmIndicator) / 3.0
            return "block_traffic" if securityIndex > 0.7 else "no_change"
    return "no_change"

def load_data(log_file):
    data = {module: [] for module in modules}
    with open(log_file, "r") as f:
        for line in f:
            record = json.loads(line)
            record["label"] = assign_label(record)
            data[record["module"]].append(record)
    return data

def extract_features(module, records):
    df = pd.DataFrame(records)
    if module == "LTM":
        for field in ["cryptoLoad", "throughputPerformance", "latency", "jitter", "packetLoss"]:
            if field not in df.columns:
                df[field] = 0
        return df[["cryptoLoad", "throughputPerformance", "latency", "jitter", "packetLoss"]]
    elif module == "APM":
        if "system.connectionsPerformance" not in df.columns:
            df["system.connectionsPerformance"] = 0
        return df[["system.connectionsPerformance"]]
    elif module == "ASM":
        if "throughputPerformance" not in df.columns:
            df["throughputPerformance"] = 0
        df["attackIndicator"] = df.apply(convert_asm_attack, axis=1)
        return df[["throughputPerformance", "attackIndicator"]]
    elif module == "SYSTEM":
        for field in ["tmmCpu", "throughputPerformance"]:
            if field not in df.columns:
                df[field] = 0
        return df[["tmmCpu", "throughputPerformance"]]
    elif module == "AFM":
        if "afmThreatScore" not in df.columns:
            df["afmThreatScore"] = 0
        return df[["afmThreatScore"]]
    return None

def train_supervised(module, records):
    X = extract_features(module, records)
    y = pd.DataFrame(records)["label"]
    clf = RandomForestClassifier(random_state=42, n_estimators=100)
    clf.fit(X, y)
    return clf

def train_rl(records, alpha=0.1):
    actions = ["scale_up", "scale_down", "discover_service", "maintain_cluster", "no_change"]
    q_table = {}
    for record in records:
        state = (round(record.get("throughputPerformance", 0), 1), convert_asm_attack(record))
        optimal_action = assign_label(record)
        if state not in q_table:
            q_table[state] = {a: 0.0 for a in actions}
        for a in actions:
            reward = 1 if a == optimal_action else 0
            q_table[state][a] += alpha * (reward - q_table[state][a])
    return q_table

def train_models(data):
    models = {}
    for module, records in data.items():
        if module == "ASM":
            print(f"Training RL agent for module {module} on {len(records)} samples.")
            models[module] = train_rl(records)
        else:
            if len(records) == 0:
                continue
            print(f"Training supervised model for module {module} on {len(records)} samples.")
            models[module] = train_supervised(module, records)
    return models

def main():
    log_file = "synthetic_ts_logs.jsonl"
    print("Loading TS log data...")
    data = load_data(log_file)
    print("Training models for each module...")
    models = train_models(data)
    with open("trained_models.pkl", "wb") as f:
        pickle.dump(models, f)
    print("Models saved to trained_models.pkl")

if __name__ == "__main__":
    main()