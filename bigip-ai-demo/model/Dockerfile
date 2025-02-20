FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY train_model.py .
COPY generate_logs.py .
# Preload synthetic logs and trained model (if available)
COPY synthetic_ts_logs.jsonl /app/models/synthetic_ts_logs.jsonl
COPY trained_models.pkl /app/models/trained_models.pkl
EXPOSE 5000
CMD ["python", "app.py"]