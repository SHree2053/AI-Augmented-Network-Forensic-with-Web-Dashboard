import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")
import os
import joblib
import pandas as pd
import numpy as np

# defining the models path
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')

# Decelaring the global variable for creating the variable locally
_binary_model = None
_multiclass_model = None
_iso_model = None
_scaler = None
_feature_names = None

def load_trained_models():
    #Load all models and feature names from the models directory.
    #Returns: (multiclass_model, iso_model, scaler, feature_names)
    # this is crucial when to share the same value or object accross different function in a program
    global _multiclass_model, _iso_model, _scaler, _feature_names

    # loading the features from local machine cretead one. 
    feature_path = os.path.join(MODELS_DIR, 'feature_columns.pkl')
    if os.path.exists(feature_path):
        _feature_names = joblib.load(feature_path)
        print(f"Loaded {len(_feature_names)} feature names.")
    else:
        raise FileNotFoundError(f"Feature columns not found: {feature_path}")

    # Loading multiclass model
    multiclass_path = os.path.join(MODELS_DIR, 'xgboost_multiclass.pkl')
    if os.path.exists(multiclass_path):
        _multiclass_model = joblib.load(multiclass_path)
        print(f"Loaded multi-class model.")
    else:
        raise FileNotFoundError(f"Multi-class model not found: {multiclass_path}")

    # loading the isoaltion model 
    iso_path = os.path.join(MODELS_DIR, 'isolation_forest.pkl')
    if os.path.exists(iso_path):
        _iso_model = joblib.load(iso_path)
        print(f"Loaded isolation forest model.")
    else:
        print(f"No isolation forest model found at {iso_path}")

    # loading scalar file
    scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
    if os.path.exists(scaler_path):
        _scaler = joblib.load(scaler_path)
        print(f"Loaded scaler.")

    return _multiclass_model, _iso_model, _scaler, _feature_names

#function used  for attack types
def predict_attack_types(features_df):
#Predict attack types using the multi-class XGBoost model.
#Returns DataFrame with is anamoly and attack type columns.
    global _binary_model, _multiclass_model, _iso_model, _scaler, _feature_names

    # loading models if not 
    if _feature_names is None:
        _, _, _, _, _feature_names = load_trained_models()

    # aliging datafreame to feaures
    X = features_df[_feature_names].copy()

    # chceking for scalar file
    if _scaler is not None:
        X_scaled = _scaler.transform(X)
    else:
        X_scaled = X.values

    # loading lable encoder file
    encoder_path = os.path.join(MODELS_DIR, 'label_encoder.pkl')
    if not os.path.exists(encoder_path):
        raise FileNotFoundError(f"Label encoder not found: {encoder_path}")

    le = joblib.load(encoder_path)

    # checking if multiclass model is not uploaded
    if _multiclass_model is None:
        multiclass_path = os.path.join(MODELS_DIR, 'xgboost_multiclass.pkl')
        _multiclass_model = joblib.load(multiclass_path)

    # variables defined for prediction
    preds_encoded = _multiclass_model.predict(X_scaled)
    attack_types = le.inverse_transform(preds_encoded)

    # Binary detection anything is not benign is anomaly
    is_anomaly = (attack_types != 'Benign')

    # Create result DataFrame with ALL columns from features_df
    result_df = features_df.copy()
    result_df['is_anomaly'] = is_anomaly
    result_df['attack_type'] = attack_types

    #  adding the placerholder if not exist
    for col in ['src_ip', 'dst_ip', 'protocol', 'length']:
        if col not in result_df.columns:
            result_df[col] = '0.0.0.0' if col in ['src_ip', 'dst_ip'] else ('TCP' if col == 'protocol' else 0)

    # Metrics for predications
    print(f"Prediction summary:")
    print(f"   - Total flows: {len(result_df)}")
    print(f"   - Anomalies: {is_anomaly.sum()}")
    print(f"   - Attack types: {pd.Series(attack_types).value_counts().to_dict()}")

    return result_df