# train_model.py

# Import necessary libraries
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import seaborn as sns
import matplotlib.pyplot as plt
import joblib

# --- 1. Load the Datasets ---
print("Loading datasets...")
try:
    df_train = pd.read_csv("UNSW_NB15_training-set.csv")
    df_test = pd.read_csv("UNSW_NB15_testing-set.csv")
except FileNotFoundError:
    print("\nERROR: Dataset files not found.")
    print("Please download the UNSW-NB15 dataset and place the files in the same directory.")
    print("Dataset URL: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/")
    exit()
print("Datasets loaded successfully.")

# --- 2. Data Preprocessing ---
print("\nPreprocessing data...")
# Drop unnecessary columns
df_train = df_train.drop(['id', 'attack_cat'], axis=1)
df_test = df_test.drop(['id', 'attack_cat'], axis=1)

# Separate features (X) and target (y)
X_train = df_train.drop('label', axis=1)
y_train = df_train['label']
X_test = df_test.drop('label', axis=1)
y_test = df_test['label']

# Identify categorical and numerical features
categorical_features = X_train.select_dtypes(include=['object']).columns
numerical_features = X_train.select_dtypes(include=np.number).columns

# Create preprocessing pipelines for numerical and categorical features
numerical_transformer = StandardScaler()
categorical_transformer = OneHotEncoder(handle_unknown='ignore')

# Create a preprocessor object using ColumnTransformer
preprocessor = ColumnTransformer(
    transformers=[
        ('num', numerical_transformer, numerical_features),
        ('cat', categorical_transformer, categorical_features)
    ],
    remainder='passthrough'
)
print("Data preprocessing complete.")

# --- 3. Model Training ---
print("\nTraining the model...")
# Define the model pipeline
model_pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                                 ('classifier', RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1))])

# Train the model
model_pipeline.fit(X_train, y_train)
print("Model training complete.")

# --- 4. Model Evaluation ---
print("\nEvaluating the model on the test set...")
y_pred = model_pipeline.predict(X_test)

# Calculate and print accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {accuracy:.4f}")

# Display and plot the confusion matrix
print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.show()

# Display the classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))

# --- 5. Save the Model and Columns ---
print("\nSaving the trained model and feature columns...")
# We save both the model pipeline and the column names for the live capture script
model_and_columns = {
    'model': model_pipeline,
    'columns': X_train.columns
}
joblib.dump(model_and_columns, 'nids_model.joblib')
print("Model saved successfully as 'nids_model.joblib'")

