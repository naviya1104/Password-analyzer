document.addEventListener('DOMContentLoaded', function() {
    // Initialize sample data if needed
    fetch('/create-sample-data')
        .then(response => response.json())
        .then(data => console.log(data.message))
        .catch(error => console.error('Error creating sample data:', error));
    
    // Get DOM elements
    const passwordInput = document.getElementById('password');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultsSection = document.getElementById('results');
    const scoreValue = document.getElementById('score-value');
    const strengthLabel = document.getElementById('strength-label');
    const gaugeInner = document.getElementById('gauge-inner');
    const lengthValue = document.getElementById('length-value');
    const lengthIcon = document.getElementById('length-icon');
    const uppercaseIcon = document.getElementById('uppercase-icon');
    const lowercaseIcon = document.getElementById('lowercase-icon');
    const numbersIcon = document.getElementById('numbers-icon');
    const specialIcon = document.getElementById('special-icon');
    const entropyValue = document.getElementById('entropy-value');
    const feedbackList = document.getElementById('feedback-list');
    const timeToCrackValue = document.getElementById('time-to-crack-value');

    // Toggle password visibility
    togglePasswordBtn.addEventListener('click', function() {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            togglePasswordBtn.textContent = 'Hide';
        } else {
            passwordInput.type = 'password';
            togglePasswordBtn.textContent = 'Show';
        }
    });
    
    // Analyze password on button click
    analyzeBtn.addEventListener('click', analyzePassword);
    
    // Also analyze on enter key press
    passwordInput.addEventListener('keyup', function(event) {
        if (event.key === 'Enter') {
            analyzePassword();
        }
    });
    
    function analyzePassword() {
        const password = passwordInput.value;
        
        if (!password) {
            alert('Please enter a password to analyze');
            return;
        }
        
        // Get API key if available
        const apiKey = localStorage.getItem('gemini_api_key');
        
        fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                password: password,
                api_key: apiKey  // Send API key to backend
            }),
        })
        .then(response => response.json())
        .then(data => {
            displayResults(data);
        })
        .catch(error => {
            console.error('Error analyzing password:', error);
            feedbackList.innerHTML = '<li>An unexpected error occurred. Please try again.</li>';
        });
    }
    
    function displayResults(data) {
        resultsSection.style.display = 'block';
        
        // Update score and strength
        scoreValue.textContent = data.score;
        strengthLabel.textContent = data.strength;
        strengthLabel.className = 'strength-label';
        
        const strengthClass = data.strength.toLowerCase().replace(' ', '-');
        strengthLabel.classList.add(strengthClass);
        
        let gaugeColor;
        if (data.score < 25) {
            gaugeColor = '#e74c3c'; // very weak (red)
        } else if (data.score < 50) {
            gaugeColor = '#e67e22'; // weak (orange)
        } else if (data.score < 65) {
            gaugeColor = '#f1c40f'; // moderate (yellow)
        } else if (data.score < 80) {
            gaugeColor = '#2ecc71'; // strong (light green)
        } else {
            gaugeColor = '#27ae60'; // very strong (dark green)
        }
        
        const angle = (data.score / 100) * 360;
        gaugeInner.style.background = `conic-gradient(${gaugeColor} 0deg ${angle}deg, var(--light-color) ${angle}deg 360deg)`;
        scoreValue.style.color = gaugeColor;
        
        lengthValue.textContent = data.length;
        lengthIcon.textContent = data.length >= 8 ? '✅' : '❌';
        
        uppercaseIcon.textContent = data.has_uppercase ? '✅' : '❌';
        lowercaseIcon.textContent = data.has_lowercase ? '✅' : '❌';
        numbersIcon.textContent = data.has_digits ? '✅' : '❌';
        specialIcon.textContent = data.has_special ? '✅' : '❌';
        
        entropyValue.textContent = data.entropy;
        timeToCrackValue.textContent = data.time_to_crack;
        
        feedbackList.innerHTML = '';
        data.feedback.forEach(item => {
            const li = document.createElement('li');
            li.textContent = item;
            feedbackList.appendChild(li);
        });
    }

    // Settings modal functionality
    const settingsBtn = document.getElementById('settings-btn');
    const settingsModal = document.getElementById('settings-modal');
    const closeModalBtn = document.querySelector('.close');
    const apiKeyInput = document.getElementById('gemini-api-key');
    const saveApiKeyBtn = document.getElementById('save-api-key');

    // Open settings modal
    settingsBtn.addEventListener('click', function(e) {
        e.preventDefault();
        settingsModal.style.display = 'block';
        
        // Load saved API key if exists
        const savedApiKey = localStorage.getItem('gemini_api_key');
        if (savedApiKey) {
            apiKeyInput.value = savedApiKey;
        }
    });

    // Close modal
    closeModalBtn.addEventListener('click', function() {
        settingsModal.style.display = 'none';
    });

    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === settingsModal) {
            settingsModal.style.display = 'none';
        }
    });

    // Save API key
    saveApiKeyBtn.addEventListener('click', function() {
        const apiKey = apiKeyInput.value.trim();
        if (apiKey) {
            localStorage.setItem('gemini_api_key', apiKey);
            alert('API key saved successfully!');
            settingsModal.style.display = 'none';
        } else {
            alert('Please enter a valid API key');
        }
    });
});