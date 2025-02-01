# ✅ Use Python 3.9 (Stable for AI Models)
FROM python:3.9

# ✅ Set Work Directory
WORKDIR /app

# ✅ Copy Requirements & AI Agent Code
COPY requirements.txt .
COPY ai_agent.py .

# ✅ Install Dependencies
RUN pip install --no-cache-dir -r requirements.txt

# ✅ Expose Port
EXPOSE 5000

# ✅ Run AI Agent
CMD ["python", "ai_agent.py"]