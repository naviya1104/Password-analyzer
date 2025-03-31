import os
import pandas as pd
import numpy as np
import re
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from password_analyzer import PasswordAnalyzer

def generate_dataset(size=10000):
    """Generate a synthetic dataset of passwords with strong/weak labels"""
    # Create a password analyzer instance without a model
    analyzer = PasswordAnalyzer(model_path=None)
    
    # Load common passwords as weak examples
    weak_passwords = []
    common_path = os.path.join('static', 'data', 'rockyou_sample.txt')
    if os.path.exists(common_path):
        with open(common_path, 'r', encoding='utf-8', errors='ignore') as f:
            weak_passwords = [line.strip() for line in f][:size//2]
    
    # If we don't have enough weak passwords, generate some simple ones
    while len(weak_passwords) < size//2:
        simple = f"password{np.random.randint(1000)}"
        weak_passwords.append(simple)
    
    # Generate strong passwords
    strong_passwords = []
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+"
    
    while len(strong_passwords) < size//2:
        length = np.random.randint(12, 20)
        password = ''.join(np.random.choice(list(chars)) for _ in range(length))
        
        # Ensure at least one uppercase, lowercase, digit, and special char
        if (re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'\d', password) and
            re.search(r'[^A-Za-z0-9]', password)):
            strong_passwords.append(password)
    
    # Create labels
    weak_labels = [0] * len(weak_passwords)
    strong_labels = [1] * len(strong_passwords)
    
    # Combine data
    all_passwords = weak_passwords + strong_passwords
    all_labels = weak_labels + strong_labels
    
    # Extract features
    features = []
    for password in all_passwords:
        features.append(analyzer._extract_features(password))
    
    return features, all_labels

def train_model():
    print("Generating dataset...")
    X, y = generate_dataset(size=10000)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    train_accuracy = model.score(X_train, y_train)
    test_accuracy = model.score(X_test, y_test)
    print(f"Train accuracy: {train_accuracy:.4f}")
    print(f"Test accuracy: {test_accuracy:.4f}")
    
    # Save model
    model_dir = os.path.join('static', 'models')
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, 'password_model.pkl')
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train_model()