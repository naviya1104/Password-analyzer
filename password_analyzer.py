import re
import math
import pickle
import os
import subprocess
from collections import Counter

class PasswordAnalyzer:
    def __init__(self, model_path=None):
        self.model_path = model_path
        self.common_passwords = set()
        self.password_model = None
        
        # Load model if provided
        if model_path and os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    self.password_model = pickle.load(f)
            except Exception as e:
                print(f"Error loading model: {e}")
        
        # Load common passwords
        data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                               'static', 'data', 'rockyou_sample.txt')
        if os.path.exists(data_path):
            try:
                with open(data_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.common_passwords = set(line.strip() for line in f)
            except Exception as e:
                print(f"Error loading common passwords: {e}")
    
    def analyze_password(self, password, max_time_to_crack=None):
        """
        Analyze password strength and return a detailed report
        """
        if not password:
            return {
                "score": 0,
                "strength": "None",
                "feedback": "Password is empty"
            }
        
        # Basic checks
        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))
        
        # Calculate character diversity
        char_set_size = sum([has_upper, has_lower, has_digit, has_special])
        
        # Check for common patterns
        has_repeated_chars = bool(re.search(r'(.)\1{2,}', password))  # 3+ repeated chars
        has_sequential_chars = self._has_sequential_pattern(password)
        
        # Check if password is common
        is_common = password.lower() in self.common_passwords
        
        # Calculate entropy
        entropy = self._calculate_entropy(password)
        
        # Use ML model prediction if available
        ml_prediction = None
        if self.password_model:
            features = self._extract_features(password)
            try:
                ml_prediction = self.password_model.predict_proba([features])[0][1]
            except:
                pass
        
        # Estimate time-to-crack using Hashcat
        time_to_crack = self._estimate_time_to_crack(password)
        
        # Calculate base score
        score = 0
        score += min(length * 4, 40)  # Length: up to 40 points
        score += 10 if has_upper else 0
        score += 10 if has_lower else 0
        score += 10 if has_digit else 0
        score += 15 if has_special else 0
        score += min(entropy * 2, 30)  # Entropy: up to 30 points
        
        # Penalties
        if is_common:
            score -= 40
        if has_repeated_chars:
            score -= 15
        if has_sequential_chars:
            score -= 15
            
        # Add ML boost if available
        if ml_prediction is not None:
            ml_score = ml_prediction * 20  # Scale to 0-20 points
            score += ml_score
        
        # Cap score between 0-100
        score = max(0, min(100, score))
        
        # Determine strength category
        strength = "Very Weak"
        if score >= 80:
            strength = "Very Strong"
        elif score >= 65:
            strength = "Strong"
        elif score >= 50:
            strength = "Moderate"
        elif score >= 25:
            strength = "Weak"
            
        # Generate feedback
        feedback = []
        if length < 8:
            feedback.append("Password is too short")
        if not has_upper:
            feedback.append("Add uppercase letters")
        if not has_lower:
            feedback.append("Add lowercase letters")
        if not has_digit:
            feedback.append("Add numbers")
        if not has_special:
            feedback.append("Add special characters")
        if has_repeated_chars:
            feedback.append("Avoid repeated characters")
        if has_sequential_chars:
            feedback.append("Avoid sequential patterns")
        if is_common:
            feedback.append("This is a commonly used password")
            
        if not feedback:
            feedback.append("Password looks good!")
        
        return {
            "time_to_crack": time_to_crack,
            "score": round(score),
            "strength": strength,
            "entropy": round(entropy, 1),
            "length": length,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digits": has_digit,
            "has_special": has_special,
            "is_common": is_common,
            "has_repeated": has_repeated_chars,
            "has_sequential": has_sequential_chars,
            "feedback": feedback
        }
    
    def _estimate_time_to_crack(self, password):
        """Estimate time-to-crack using Hashcat"""
        import subprocess
        
        # Command to run Hashcat for time-to-crack estimation
        command = f"hashcat -a 0 -m 0 --quiet --stdout {password}"
        
        try:
            # Execute the Hashcat command
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            # Parse the output to get the estimated time-to-crack
            output = result.stdout.strip()
            return output  # Return the output from Hashcat
        except Exception as e:
            print(f"Error estimating time-to-crack: {e}")
            return "Error estimating time"
    
    def _has_sequential_pattern(self, password):
        """Check for sequential patterns like 'abc', '123', etc."""
        common_sequences = [
            "abcdefghijklmnopqrstuvwxyz",
            "qwertyuiop", "asdfghjkl", "zxcvbnm",
            "0123456789"
        ]
        
        password_lower = password.lower()
        for seq in common_sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in password_lower:
                    return True
        return False
    
    def _calculate_entropy(self, password):
        """Calculate Shannon entropy of the password"""
        if not password:
            return 0
            
        freq = Counter(password)
        length = len(password)
        
        entropy = 0
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
            
        return entropy * length / 3  # Scale entropy by length/3 for better scoring
    
    def _extract_features(self, password):
        """Extract features for ML model"""
        length = len(password)
        has_upper = int(bool(re.search(r'[A-Z]', password)))
        has_lower = int(bool(re.search(r'[a-z]', password)))
        has_digit = int(bool(re.search(r'\d', password)))
        has_special = int(bool(re.search(r'[^A-Za-z0-9]', password)))
        entropy = self._calculate_entropy(password)
        char_classes = has_upper + has_lower + has_digit + has_special
        
        return [
            length, 
            has_upper,
            has_lower, 
            has_digit, 
            has_special, 
            entropy,
            char_classes
        ]
