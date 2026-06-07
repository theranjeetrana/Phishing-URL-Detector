from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os
import sys
import whois
from datetime import datetime

# Ensure Python can find your local utils.py file cleanly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils import extract_features

app = Flask(__name__)
# Enable CORS so your frontend folder can securely talk to this backend port
CORS(app)

# 1. Load the AI Brain (the trained .pkl model)
model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
try:
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
except FileNotFoundError:
    print("ERROR: phishing_model.pkl not found! Please check your backend folder.")

# --- FEATURE B: LIVE NETWORK WHOIS DOMAIN AGE AUDIT ---
def get_domain_age_days(url):
    try:
        # Extract clean domain name from raw URL path string
        domain = url.split('/')[0] if "://" not in url else url.split('//')[1].split('/')[0]
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age = (datetime.now() - creation_date).days
            return age, creation_date.strftime('%Y-%m-%d')
        return "Unknown", "Unknown"
    except Exception:
        return "Unknown", "Unknown" # If domain registration hidden or connection drops

# --- ROUTE FOR SINGLE URL SCANS (FEATURE A & B) ---
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '').lower().strip()
    
    if not url:
        return jsonify({'error': 'No URL trajectory provided'}), 400

    # 1. Extract values & Deep Forensics (FEATURE A)
    features, forensics = extract_features(url)
    
    # 2. Dynamic Infrastructure query (FEATURE B)
    domain_age, creation_str = get_domain_age_days(url)
    forensics['domain_age_days'] = domain_age
    forensics['creation_date'] = creation_str
    
    # 3. AI Inference Match
    prediction = model.predict([features])[0]
    
    # --- BALANCED SECURITY RULE ENGINE OVERRIDES ---
    is_phishing_prediction = (prediction == 1)
    is_typosquatting = (forensics['typosquatting_detected'] == "Yes")
    has_dangerous_keywords = (forensics['keyword_triggered'] == "Yes")
    is_brand_new_domain = (isinstance(domain_age, int) and domain_age < 14)
    
    # BALANCED OVERRIDE: Only flag an "Unknown" age layout if the ML model already suspects 
    # it OR if it carries deceptive target keywords. This protects safe assets like google.com.
    is_suspicious_hidden_domain = (domain_age == "Unknown" and (is_phishing_prediction or has_dangerous_keywords))

    if (is_phishing_prediction or 
        is_typosquatting or 
        has_dangerous_keywords or 
        is_brand_new_domain or 
        is_suspicious_hidden_domain):
        
        result = "PHISHING"
    else:
        result = "SAFE"
        
    return jsonify({
        'result': result,
        'url': url,
        'forensics': forensics
    })

# --- ULTIMATE FEATURE C: UNIVERSAL BATCH LOG SCANNER (.CSV / .TXT INGESTION) ---
@app.route('/bulk-scan', methods=['POST'])
def bulk_scan():
    if 'file' not in request.files:
        return jsonify({'error': 'No file element detected in pipeline'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename uploaded'}), 400
        
    try:
        # Read file as a direct raw text stream to completely avoid header error crashes
        file_bytes = file.read().decode('utf-8', errors='ignore')
        raw_lines = [line.strip() for line in file_bytes.splitlines() if line.strip()]
        
        if not raw_lines:
            return jsonify({'error': 'The uploaded database threat ledger is empty'}), 400
            
        # If the user uploaded a CSV that includes the header text 'url', gracefully skip it
        if raw_lines[0].lower() == 'url':
            target_urls = raw_lines[1:]
        else:
            target_urls = raw_lines
            
        results = []
        detailed_results = [] # Dynamic array map pairing urls directly with verdicts
        
        # Process every line instantly through our machine learning pipeline
        for raw_url in target_urls:
            feat, forensic_data = extract_features(str(raw_url))
            pred = model.predict([feat])[0]
            
            # Apply identical keyword protection rules inside the bulk processor
            if pred == 1 or forensic_data['typosquatting_detected'] == "Yes" or forensic_data['keyword_triggered'] == "Yes":
                status = "Phishing"
            else:
                status = "Safe"
                
            results.append(status)
            detailed_results.append({
                'url': raw_url,
                'status': status
            })
            
        return jsonify({
            'message': 'Bulk batch operation completed successfully',
            'total_scanned': len(target_urls),
            'phishing_count': results.count('Phishing'),
            'safe_count': results.count('Safe'),
            'detailed_results': detailed_results # Exposing inner mappings to frontend engine
        })
        
    except Exception as e:
        return jsonify({'error': f"Internal engine parsing failure: {str(e)}"}), 500

if __name__ == '__main__':
    print("----------------------------------------------------------------")
    print("PHISHING URL DETECTOR IS NOW LIVE ")
    print("----------------------------------------------------------------")
    app.run(debug=True, port=5000)