# F5 Agent - PoC - AI-driven Security system with BIG-IP and CIS

*Install the below python 3.9 packages*

pip install pandas scikit-learn xgboost joblib tensorflow imblearn lightgbm xgboost

*Compile AI model*

python3 ai_model.py

sample ouput:
```
 > python3 ai_model.py                                                                                                 
Model Accuracy Scores:
XGBoost CV Accuracy: 0.8987
LightGBM CV Accuracy: 0.8991
MLP CV Accuracy: 0.9000
Noisy Test Set Accuracy: 1.0000

Deploying Best Model: MLP

Best Model (MLP) successfully exported to TensorFlow format at: models/anomaly_model_tf
```

*Build docker container*
docker build -t quay.io/trinathsquay/asm-anomaly-model:latest . && docker push quay.io/trinathsquay/asm-anomaly-model:latest
