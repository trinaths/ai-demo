# Use a lightweight Python image.
FROM python:3.9-slim

# Set the working directory.
WORKDIR /app

# Copy only the dependency list and install packages.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code (model training, inference, and log generation).
# Note: We assume that synthetic logs and trained models are provided at runtime via PV/PVC.
COPY app.py .
COPY train_model.py .
COPY generate_logs.py .

# Expose the port the model service will use.
EXPOSE 5000

# Command to run the model service.
CMD ["python", "app.py"]