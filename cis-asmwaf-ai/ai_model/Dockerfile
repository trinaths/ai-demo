FROM tensorflow/serving:latest

# Ensure model is copied from the correct path
COPY models/anomaly_model_tf /models/anomaly_model_tf

ENV MODEL_NAME=anomaly_model_tf

ENTRYPOINT ["/usr/bin/tensorflow_model_server", "--model_base_path=/models/anomaly_model_tf", "--rest_api_port=8501", "--model_name=anomaly_model_tf"]