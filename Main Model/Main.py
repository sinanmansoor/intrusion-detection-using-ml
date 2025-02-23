import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

# Load the trained model
model = joblib.load("intrusion_detection_model.pkl")
print("✅ Model loaded successfully!")
filepath = "network_security_dataset.csv"
# Load sample test data
def load_test_data(filepath):
    """
    Load and preprocess new test data
    """
    data = pd.read_csv(filepath, low_memory=False)

    # Encode categorical columns (Adjust based on your dataset)
    categorical_columns = ['protocol_type', 'service', 'flag']
    for col in categorical_columns:
        data[col] = data[col].astype('category').cat.codes  # Convert to numeric

    # Select numeric features
    numeric_columns = data.select_dtypes(include=[np.number]).columns.tolist()

    # Scale the features
    scaler = StandardScaler()
    X_test_scaled = scaler.fit_transform(data[numeric_columns])

    return X_test_scaled, data

# Path to new test dataset
test_data_path = "new_test_data.csv"  # Change this to your actual test data file

# Load and preprocess test data
X_test_scaled, original_data = load_test_data(test_data_path)

# Make predictions
predictions = model.predict(X_test_scaled)

# Add predictions to original data
original_data["predicted_attack"] = predictions

# Save results
original_data.to_csv("predictions_output.csv", index=False)
print("✅ Predictions saved in 'predictions_output.csv'!")

# Display first few results
print(original_data[['label', 'predicted_attack']].head())
