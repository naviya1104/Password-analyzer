import os
import requests
import json
import logging

# Load environment variable for Gemini API Key
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

if not GEMINI_API_KEY:
    logging.warning("No Gemini API key found. AI recommendations will be disabled.")

def call_gemini_api(prompt):
    """Call the Gemini API with the provided prompt."""
    if not GEMINI_API_KEY:
        logging.error("API key is missing.")
        return None

    logging.debug(f"Calling Gemini API with prompt: {prompt}")  # Log the prompt being sent
    payload = {
        "contents": [{
            "parts": [{
                "text": prompt
            }]
        }]
    }

    try:
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}",
            headers=headers,
            data=json.dumps(payload)
        )

        logging.debug(f"Gemini API response: {response.status_code} - {response.text}")
        if response.status_code == 200 and 'candidates' in response.json():
            return response.json()
        else:
            logging.error(f"API Error: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        logging.error(f"Error calling Gemini API: {e}")
        return None
