# Use TensorFlow Serving as the base image
FROM tensorflow/serving:latest

# Copy the trained AI model into the container
COPY models/anomaly_model /models/anomaly_model

# Set environment variables for TensorFlow Serving
ENV MODEL_NAME=anomaly_model
ENV MODEL_BASE_PATH=/models/anomaly_model

# ✅ Correct ENTRYPOINT Syntax for TensorFlow Serving
ENTRYPOINT ["/usr/bin/tensorflow_model_server", \
            "--port=8500", \
            "--rest_api_port=8501", \
            "--model_name=anomaly_model", \
            "--model_base_path=/models/anomaly_model"]