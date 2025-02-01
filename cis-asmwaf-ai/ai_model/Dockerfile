# Use official Python image as base
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy requirements.txt and install dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Flask app, model, and scaler file into the container
COPY app.py /app
COPY ai_model.joblib /app
COPY scaler.joblib /app  # If you saved the scaler during training

# Expose port 5000 for the Flask app
EXPOSE 5000

# Start the Flask app when the container runs
CMD ["python", "app.py"]