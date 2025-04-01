# Password Strength Analyzer

## Overview
The Password Strength Analyzer is an intelligent tool that analyzes password strength using various metrics and provides suggestions for improvement. It utilizes machine learning techniques and integrates with the Gemini API to recommend stronger passwords and explain weaknesses.

## Features
- Analyzes password strength based on length, character diversity, common patterns, and entropy.
- Estimates time-to-crack using Hashcat.
- Provides feedback on how to improve password strength.
- Integrates with the Gemini API to suggest stronger passwords and provide reasoning for weaknesses.

## Usage
1. **Initialize the Password Analyzer**:
   ```python
   from password_analyzer import PasswordAnalyzer
   analyzer = PasswordAnalyzer(model_path='path/to/your/model.pkl')
   ```

2. **Analyze a Password**:
   ```python
   result = analyzer.analyze_password('your_password_here')
   print(result)
   ```

3. **Gemini API Integration**:
   - The tool will automatically call the Gemini API to get suggestions for stronger passwords and reasoning for weaknesses.
   - Suggestions will be included in the analysis report.

## Requirements
- Python 3.x
- Requests library for API calls
- Hashcat for time-to-crack estimation

## Installation
Install the required libraries:
```bash
pip install requests
```

## License
This project is licensed under the MIT License.
