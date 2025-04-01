from flask import Flask, render_template, request, jsonify
import os
import logging
from password_analyzer import PasswordAnalyzer

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Load environment variable for Gemini API Key
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

if not GEMINI_API_KEY:
    try:
        from dotenv import load_dotenv
        load_dotenv()
        GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
    except ImportError:
        logging.warning("dotenv not installed, can't load .env file")

# Warn if API key is missing
if not GEMINI_API_KEY:
    logging.warning("No Gemini API key found. AI recommendations will be disabled.")

# Initialize password analyzer
model_path = os.path.join('static', 'models', 'password_model.pkl')
# Initialize the PasswordAnalyzer with the correct model path
analyzer = PasswordAnalyzer(model_path=model_path)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/model-accuracy', methods=['GET'])
def model_accuracy():
    """Retrieve the accuracy of the trained model."""
    try:
        model_path = os.path.join('static', 'models', 'password_model.pkl')
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            # Assuming the model has a method to retrieve accuracy
            accuracy = analyzer.get_model_accuracy()  # Call the method to get accuracy
            return jsonify({"accuracy": accuracy}), 200
        else:
            return jsonify({"error": "Model not found."}), 404
    except Exception as e:
        logging.error(f"Error retrieving model accuracy: {e}")
        return jsonify({"error": "An error occurred while retrieving model accuracy."}), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    password = data.get('password', '')
    max_time_to_crack = data.get('max_time_to_crack', None)  # New parameter
    api_key = data.get('api_key')
    
    # Set API key if provided
    if api_key:
        os.environ['GEMINI_API_KEY'] = api_key
    
    # Validate max_time_to_crack
    if max_time_to_crack is not None:
        try:
            max_time_to_crack = float(max_time_to_crack)
            if max_time_to_crack < 0:
                raise ValueError("Max time to crack must be a non-negative number.")
        except ValueError as e:
            logging.error(f"Invalid max_time_to_crack: {e}")
            return jsonify({"feedback": ["Invalid max_time_to_crack value. It must be a non-negative number."]}), 400
    
    try:
        result = analyzer.analyze_password(password, max_time_to_crack)  # Updated call
        logging.debug(f"Analysis result: {result}")  # Log the result
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error analyzing password: {e}")
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
    app.run(debug=True)
