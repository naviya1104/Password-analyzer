from flask import Flask, render_template, request, jsonify
import os
import logging
from password_analyzer import PasswordAnalyzer

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Initialize password analyzer
model_path = os.path.join('static', 'models', 'password_model.pkl')
analyzer = PasswordAnalyzer(model_path=model_path if os.path.exists(model_path) else None)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    password = data.get('password', '')
    max_time_to_crack = data.get('max_time_to_crack', None)  # New parameter
    
    try:
        result = analyzer.analyze_password(password, max_time_to_crack)  # Updated call
        logging.debug(f"Analysis result: {result}")  # Log the result
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error analyzing password: {e}")
        # Return a user-friendly message without exposing error details
        # Always return feedback without indicating an error occurred
        return jsonify({"feedback": ["An unexpected issue occurred. Please try again."]}), 200

@app.route('/create-sample-data', methods=['GET'])
def create_sample_data():
    """Create sample data file if it doesn't exist"""
    data_dir = os.path.join('static', 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    sample_path = os.path.join(data_dir, 'rockyou_sample.txt')
    
    if not os.path.exists(sample_path):
        # Create a small sample of common passwords
        common_passwords = [
            "password", "123456", "qwerty", "admin", "welcome",
            "password123", "abc123", "letmein", "monkey", "1234567890",
            "trustno1", "dragon", "baseball", "football", "superman",
            "princess", "123123", "987654321", "master", "hello",
            "shadow", "sunshine", "iloveyou", "welcome1", "password1"
        ]
        
        with open(sample_path, 'w') as f:
            f.write('\n'.join(common_passwords))
        
        return jsonify({"success": True, "message": "Sample data created"})
    
    return jsonify({"success": True, "message": "Sample data already exists"})

if __name__ == '__main__':
    # Create sample data file if needed
    app.route('/create-sample-data')(lambda: create_sample_data())
    
    # Run the app
    app.run(debug=True)