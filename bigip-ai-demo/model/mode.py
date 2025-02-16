import json
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

try:
    from stable_baselines3 import PPO
    import gym
    from gym import spaces
    stable_baselines_available = True
except ImportError:
    stable_baselines_available = False
    print("⚠️ Warning: stable_baselines3 is not installed. RL models will not be trained.")

# Define log files and AI use cases
log_files = {
    "ssl_offloading": "ssl_offloading_logs.json",
    "traffic_steering_sla": "traffic_steering_sla_logs.json",
    "ingress_egress_routing": "ingress_egress_routing_logs.json",
    "auto_scaling_service_discovery": "auto_scaling_service_discovery_logs.json",
    "cluster_resilience": "cluster_resilience_logs.json"
}

# Define target labels
use_case_types = {
    "ssl_offloading": "supervised",
    "traffic_steering_sla": "reinforcement",
    "ingress_egress_routing": "reinforcement",
    "auto_scaling_service_discovery": "supervised",
    "cluster_resilience": "reinforcement"
}

# Train Supervised Learning Models
def train_supervised_model(log_file, target_label):
    if not os.path.exists(log_file):
        print(f"⚠️ Warning: Log file {log_file} not found. Skipping model training for {target_label}.")
        return None

    with open(log_file, "r") as f:
        logs = json.load(f)

    data = []
    for log in logs:
        entry = {
            "cpuUsage": log.get("system", {}).get("cpu", 50),
            "memoryUsage": log.get("system", {}).get("memory", 50),
            "connections": log.get("virtualServers", {}).get("/Common/vs_https", {}).get("clientside.curConns", 500),
            "latency": log.get("response", {}).get("latency", 100),
            "bitsIn": log.get("virtualServers", {}).get("/Common/vs_https", {}).get("clientside.bitsIn", 100000),
            "bitsOut": log.get("virtualServers", {}).get("/Common/vs_https", {}).get("clientside.bitsOut", 100000),
            target_label: 1 if log.get("system", {}).get("cpu", 50) > 80 else 0
        }
        data.append(entry)

    df = pd.DataFrame(data)
    X = df.drop(columns=[target_label])
    y = df[target_label]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)
    model_filename = f"{target_label}_model.pkl"
    joblib.dump(model, model_filename)
    print(f"Supervised model trained: {model_filename}")
    return model

# Define RL Environment for BIG-IP
def create_rl_env():
    class BIGIPEnv(gym.Env):
        def __init__(self):
            super(BIGIPEnv, self).__init__()
            self.observation_space = spaces.Box(low=0, high=100, shape=(4,), dtype=np.float32)
            self.action_space = spaces.Discrete(3)
            self.state = np.array([50, 50, 500, 5000], dtype=np.float32)
            self.done = False

        def step(self, action):
            cpu, memory, traffic, connections = self.state
            if action == 1:
                cpu -= 10
                memory += 5
                reward = 10 if cpu < 70 else -5
            elif action == 2:
                traffic -= 200
                reward = 10 if traffic < 1000 else -5
            else:
                cpu += 5
                reward = -10 if cpu > 85 else 5
            self.state = np.array([cpu, memory, traffic, connections], dtype=np.float32)
            self.done = cpu < 40 or cpu > 95
            return self.state, reward, self.done, {}

        def reset(self):
            self.state = np.array([50, 50, 500, 5000], dtype=np.float32)
            self.done = False
            return self.state

    return BIGIPEnv()

# Train RL Models
def train_rl_model(model_name):
    if not stable_baselines_available:
        print(f"⚠️ Skipping RL model training for {model_name} due to missing stable_baselines3.")
        return None
    
    env = create_rl_env()
    model = PPO("MlpPolicy", env, verbose=1)
    model.learn(total_timesteps=10000)
    model.save(f"{model_name}_rl_model")
    print(f"RL model trained: {model_name}_rl_model")
    return model

# Train models for each AI use case
trained_models = {}
for use_case, model_type in use_case_types.items():
    if model_type == "supervised":
        trained_models[use_case] = train_supervised_model(log_files[use_case], use_case)
    elif model_type == "reinforcement":
        trained_models[use_case] = train_rl_model(use_case)

print("All AI models trained successfully for BIG-IP TS logs.")
