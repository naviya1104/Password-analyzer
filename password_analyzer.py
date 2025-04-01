import re
import math
import pickle
import os
import logging
from collections import Counter
import requests
import json
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# Access the Gemini API key
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

if GEMINI_API_KEY:
    logging.info("Gemini API key loaded successfully!")
else:
    logging.warning("Gemini API key not found!")

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
                    logging.info("Password model loaded successfully")
            except Exception as e:
                logging.error(f"Error loading model: {e}")
        
        # Load common passwords
        data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                               'static', 'data', 'rockyou_sample.txt')
        if os.path.exists(data_path):
            try:
                with open(data_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.common_passwords = set(line.strip() for line in f)
                    logging.info(f"Loaded {len(self.common_passwords)} common passwords")
            except Exception as e:
                logging.error(f"Error loading common passwords: {e}")
    
    def get_model_accuracy(self):
        """Retrieve the accuracy of the trained model."""
        try:
            # Load test data for evaluation
            from train_model import generate_dataset
            X, y = generate_dataset(size=1000)  # Create a small test set
            
            # Evaluate model on this data
            if self.password_model:
                accuracy = self.password_model.score(X, y)
                logging.info(f"Model accuracy: {accuracy:.4f}")
                return round(accuracy * 100, 2)  # Return as percentage rounded to 2 decimal places
            else:
                logging.warning("No model loaded to evaluate")
                return None
        except Exception as e:
            logging.error(f"Error calculating model accuracy: {e}")
            return None

    def analyze_password(self, password, max_time_to_crack=None):
        """
        Analyze password strength and return a detailed report
        """
        logging.debug(f"Analyzing password length: {len(password)}")  # Log only length for security
        if not password:
            return {
                "score": 0,
                "strength": "None",
                "feedback": ["Password is empty"]
            }
        
        # Basic checks
        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))
        
        # Calculate character diversity
        char_set_size = sum([has_upper, has_lower, has_digit, has_special])
        
        # Pattern checks
        has_repeated_chars = bool(re.search(r'(.)\1{2,}', password))  # 3+ repeated chars
        has_sequential_chars = self._has_sequential_pattern(password)
        
        # Check for common words or patterns
        has_common_words = self._contains_common_words(password)
        has_keyboard_pattern = self._has_keyboard_pattern(password)
        has_date_pattern = self._has_date_pattern(password)
        
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
                logging.debug(f"ML prediction: {ml_prediction:.4f}")
            except Exception as e:
                logging.error(f"Error in ML prediction: {e}")
        
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
        if has_keyboard_pattern:
            score -= 10
        if has_date_pattern:
            score -= 10
        if has_common_words:
            score -= 20
            
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
        weakness_reasons = []
        
        # Basic feedback for common issues
        if length < 8:
            feedback.append("Password is too short (minimum 8 characters recommended)")
            weakness_reasons.append("Password is too short")
        if not has_upper:
            feedback.append("Add uppercase letters (A-Z)")
            weakness_reasons.append("No uppercase letters")
        if not has_lower:
            feedback.append("Add lowercase letters (a-z)")
            weakness_reasons.append("No lowercase letters")
        if not has_digit:
            feedback.append("Add numbers (0-9)")
            weakness_reasons.append("No numbers")
        if not has_special:
            feedback.append("Add special characters (!@#$%^&*)")
            weakness_reasons.append("No special characters")
        
        # Advanced pattern feedback
        if has_repeated_chars:
            feedback.append("Avoid repeated characters (e.g., 'aaa', '111')")
            weakness_reasons.append("Contains repeated characters")
        if has_sequential_chars:
            feedback.append("Avoid sequential patterns (e.g., 'abc', '123')")
            weakness_reasons.append("Contains sequential patterns")
        if has_keyboard_pattern:
            feedback.append("Avoid keyboard patterns (e.g., 'qwerty', 'asdfgh')")
            weakness_reasons.append("Contains keyboard patterns")
        if has_date_pattern:
            feedback.append("Avoid using dates, which are easily guessable")
            weakness_reasons.append("Contains date patterns")
        if has_common_words:
            feedback.append("Avoid using common words or names")
            weakness_reasons.append("Contains common words")
        if is_common:
            feedback.append("This is a commonly used password that's likely in hackers' dictionaries")
            weakness_reasons.append("Is a commonly used password")
            
        if not feedback:
            feedback.append("Password looks good!")
        
        # Generate improved password suggestions
        improved_suggestion = self._generate_improved_password(password, weakness_reasons)
        
        # Estimate time to crack using zxcvbn-inspired approach
        time_to_crack = self._estimate_time_to_crack_improved(password)
        
        # Check if the password meets the time-to-crack requirement
        if max_time_to_crack is not None and time_to_crack["seconds"] < max_time_to_crack:
            feedback.append(f"Password doesn't meet the required strength (needs to take longer than {self._format_time(max_time_to_crack)} to crack)")
        
        result = {
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
            "has_keyboard_pattern": has_keyboard_pattern,
            "has_date_pattern": has_date_pattern,
            "has_common_words": has_common_words,
            "feedback": feedback,
            "weakness_reasons": weakness_reasons,
            "improved_suggestion": improved_suggestion,
            "time_to_crack": time_to_crack["text"],
            "time_to_crack_seconds": time_to_crack["seconds"],
            "password_masked": '*' * length
        }
        
        # Get AI-powered recommendations if API key is available
        if GEMINI_API_KEY:
            try:
                ai_recommendations = self.get_genai_recommendations(result)
                if ai_recommendations:
                    result.update(ai_recommendations)
            except Exception as e:
                logging.error(f"Error retrieving AI recommendations: {e}")
    
        return result
    
    def _contains_common_words(self, password):
        """Check if password contains common words"""
        common_words = ["password", "admin", "user", "login", "welcome", 
                      "secret", "qwerty", "letmein", "monkey", "dragon", 
                      "baseball", "football", "superman", "batman", "trustno",
                      "summer", "winter", "spring", "autumn", "apple"]
        
        password_lower = password.lower()
        for word in common_words:
            if word in password_lower:
                return True
        return False
    
    def _has_keyboard_pattern(self, password):
        """Check for keyboard patterns like 'qwerty', 'asdfgh', etc."""
        keyboard_patterns = [
            "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn", "qweasdzxc",
            "1qaz2wsx", "qazwsx", "zxcvbnm", "poiuyt", "lkjhgf"
        ]
        
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                return True
            
        # Check for rows on keyboard
        for i in range(len(password) - 2):
            segment = password_lower[i:i+3]
            if segment in "qwertyuiop" or segment in "asdfghjkl" or segment in "zxcvbnm":
                return True
                
        return False
    
    def _has_date_pattern(self, password):
        """Check for date patterns"""
        # Check for MMDDYYYY, DDMMYYYY, MMDDYY, DDMMYY
        date_patterns = [
            r'\d{2}[/\-_.]\d{2}[/\-_.]\d{2,4}',  # MM/DD/YYYY
            r'\d{4,8}',  # YYYYMMDD or MMDDYYYY without separators
            r'19\d{2}|20\d{2}'  # Years (1900-2099)
        ]
        
        for pattern in date_patterns:
            if re.search(pattern, password):
                return True
        return False
    
    def _generate_improved_password(self, original, weakness_reasons):
        """Generate improved password suggestions based on the original and its weaknesses"""
        improved = original
        
        # If too short, add characters
        if "Password is too short" in weakness_reasons and len(improved) < 12:
            improved += "Str0ng!"[:12-len(improved)]
            
        # If no uppercase, add some
        if "No uppercase letters" in weakness_reasons:
            for i in range(len(improved)):
                if improved[i].islower():
                    improved = improved[:i] + improved[i].upper() + improved[i+1:]
                    break
        
        # If no lowercase, add some
        if "No lowercase letters" in weakness_reasons:
            for i in range(len(improved)):
                if improved[i].isupper():
                    improved = improved[:i] + improved[i].lower() + improved[i+1:]
                    break
        
        # If no numbers, add one
        if "No numbers" in weakness_reasons:
            improved += "9"
            
        # If no special chars, add one
        if "No special characters" in weakness_reasons:
            improved += "!"
            
        # Replace sequential or common patterns
        if "Contains sequential patterns" in weakness_reasons or "Contains keyboard patterns" in weakness_reasons:
            for pattern in ["123", "abc", "qwe", "asd", "zxc"]:
                improved = improved.replace(pattern, "q8Z")
        
        # If it's a common password, transform it more significantly
        if "Is a commonly used password" in weakness_reasons or "Contains common words" in weakness_reasons:
            # Leet speak replacements
            leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
            for char, replacement in leet_map.items():
                improved = improved.replace(char, replacement)
            
            # Add complexity
            if len(improved) < 12:
                improved += "K!9z"
        
        # Make sure it's different from the original
        if improved == original:
            # Apply basic leet speak
            improved = ''.join([
                '4' if c == 'a' else
                '3' if c == 'e' else
                '1' if c == 'i' else
                '0' if c == 'o' else
                '5' if c == 's' else
                '7' if c == 't' else c
                for c in improved
            ])
            
            # Still the same? Add a special ending
            if improved == original:
                improved += "#2Fx!"
        
        return improved
    
    def get_genai_recommendations(self, analysis_result):
        """Get AI-powered recommendations using Google's Gemini API"""
        # Construct the prompt
        strength = analysis_result['strength']
        password_masked = analysis_result.get('password_masked', '********')  # Don't use actual password!
        weakness_reasons = analysis_result.get('weakness_reasons', [])
        
        # Create prompt with analysis information but without the actual password
        prompt = f"""
        I need detailed recommendations for improving a password with the following characteristics:
        - Strength rating: {strength}
        - Length: {analysis_result['length']}
        - Has uppercase: {analysis_result['has_uppercase']}
        - Has lowercase: {analysis_result['has_lowercase']}
        - Has digits: {analysis_result['has_digits']}
        - Has special characters: {analysis_result['has_special']}
        - Is common password: {analysis_result['is_common']}
        - Has repeated characters: {analysis_result['has_repeated']}
        - Has sequential patterns: {analysis_result['has_sequential']}
        - Has keyboard patterns: {analysis_result['has_keyboard_pattern']}
        - Has date patterns: {analysis_result['has_date_pattern']}
        - Contains common words: {analysis_result['has_common_words']}
        - Entropy score: {analysis_result['entropy']}
        - Estimated time to crack: {analysis_result['time_to_crack']}
        
        The main reasons this password is weak are: {', '.join(weakness_reasons)}
        
        Provide:
        1. A detailed explanation of the security risks associated with this specific type of password
        2. Exactly why this password is {strength.lower()} (focus on specific vulnerabilities)
        3. Actionable suggestions for creating a stronger password (3-5 specific tips)
        4. An example of a stronger password that follows a similar pattern but addresses the weaknesses
        
        Important: Do not include speculative information about the actual password - only use the analysis data provided above.
        Format your response in a concise, user-friendly way with clearly separated sections.
        """
        
        # API request payload
        payload = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }]
        }
        
        # Call Gemini API
        try:
            headers = {
                "Content-Type": "application/json"
            }
            # Use Gemini API with your GEMINI_API_KEY
            response = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}",
                headers=headers,
                data=json.dumps(payload)
            )
            
            logging.debug(f"Gemini API response code: {response.status_code}")
            if response.status_code == 200 and 'candidates' in response.json():
                result = response.json()
                # Extract the text from the response
                if 'candidates' in result and len(result['candidates']) > 0:
                    genai_text = result['candidates'][0]['content']['parts'][0]['text']
                    
                    # Process the response to extract structured sections
                    sections = self._parse_ai_response(genai_text)
                    
                    return {
                        "ai_explanation": sections.get("explanation", []),
                        "ai_vulnerabilities": sections.get("vulnerabilities", []),
                        "ai_suggestions": sections.get("suggestions", []),
                        "ai_example": sections.get("example", None),
                        "ai_full_response": genai_text
                    }
                else:
                    logging.error(f"No valid candidates returned from Gemini API")
                    return None
            else:
                logging.error(f"API Error: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"Error calling Gemini API: {e}")
            return None
    
    def _parse_ai_response(self, response_text):
        """Parse the AI response into structured sections"""
        sections = {
            "explanation": [],
            "vulnerabilities": [],
            "suggestions": [],
            "example": None
        }
        
        current_section = None
        
        for line in response_text.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Identify sections
            lower_line = line.lower()
            if any(term in lower_line for term in ["security risk", "risk", "explanation"]) and not line.startswith('-'):
                current_section = "explanation"
                continue
            elif any(term in lower_line for term in ["why", "vulnerabilit", "weakness"]) and not line.startswith('-'):
                current_section = "vulnerabilities"
                continue
            elif any(term in lower_line for term in ["suggestion", "recommend", "improve", "tip"]) and not line.startswith('-'):
                current_section = "suggestions"
                continue
            elif any(term in lower_line for term in ["example", "stronger password"]) and not line.startswith('-'):
                current_section = "example"
                continue
                
            # Process content based on current section
            if current_section == "example":
                if ':' in line:
                    sections["example"] = line.split(':', 1)[1].strip()
                else:
                    sections["example"] = line
            elif current_section and line.startswith(('-', '•', '*', '1.', '2.', '3.', '4.', '5.')):
                item = line.lstrip('-•* 123456789.').strip()
                if item and current_section in sections:
                    sections[current_section].append(item)
        
        return sections
    
    def _estimate_time_to_crack_improved(self, password):
        """
        Estimate time-to-crack based on password complexity
        Returns both seconds and human-readable format
        """
        # Calculate character set size
        char_set_size = 0
        if re.search(r'[a-z]', password):
            char_set_size += 26
        if re.search(r'[A-Z]', password):
            char_set_size += 26
        if re.search(r'\d', password):
            char_set_size += 10
        if re.search(r'[^A-Za-z0-9]', password):
            char_set_size += 33  # Common special characters
            
        # Default to smallest reasonable charset
        if char_set_size == 0:
            char_set_size = 26
            
        # Assume average of 10 billion guesses per second (modern password cracker)
        guesses_per_second = 10_000_000_000
        
        # Calculate total possible combinations
        combinations = char_set_size ** len(password)
        
        # On average, a brute force attack finds the password after trying half the combinations
        seconds = combinations / (2 * guesses_per_second)
        
        # Common password penalty - if it's a common pattern, drastically reduce the time
        if password.lower() in self.common_passwords:
            seconds = min(seconds, 0.1)  # Instant cracking for common passwords
            
        # Check for common patterns and apply penalties
        if self._has_sequential_pattern(password) or self._has_keyboard_pattern(password):
            seconds /= 1000  # Much faster to crack with pattern-based attacks
            
        if self._has_date_pattern(password):
            seconds /= 500  # Date patterns are quickly checked in attacks
            
        # Apply length penalty for very short passwords
        if len(password) < 8:
            seconds /= 100
            
        # Format the time in a human-readable way
        readable_time = self._format_time(seconds)
        
        return {
            "seconds": seconds,
            "text": readable_time
        }
    
    def _format_time(self, seconds):
        """Format seconds into a human-readable time string"""
        if seconds < 0.001:
            return "Instantly"
        if seconds < 1:
            return "Less than a second"
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        if seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        if seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
        if seconds < 2592000:  # 30 days
            days = seconds / 86400
            return f"{days:.1f} days"
        if seconds < 31536000:  # 365 days
            months = seconds / 2592000
            return f"{months:.1f} months"
        if seconds < 315360000:  # 10 years
            years = seconds / 31536000
            return f"{years:.1f} years"
        if seconds < 3153600000:  # 100 years
            decades = seconds / 315360000
            return f"{decades:.1f} decades"
        if seconds < 31536000000:  # 1,000 years
            centuries = seconds / 3153600000
            return f"{centuries:.1f} centuries"
            
        return "Millions of years"
    
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