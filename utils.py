import re
from urllib.parse import urlparse
import Levenshtein

def extract_features(url):
    url = str(url).lower()
    domain = urlparse(url).netloc if "://" in url else url.split('/')[0]
    
    # 1. Structural Calculations
    url_len = len(url)
    dot_count = url.count('.')
    hyphen_count = url.count('-')
    
    # 2. Sensitive Keyword Check
    sensitive_words = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'billing', 'free', 'iphone']
    has_keywords = 1 if any(word in url for word in sensitive_words) else 0
    
    # 3. Typosquatting Calculation (Levenshtein)
    popular_domains = ['google.com', 'amazon.com', 'facebook.com', 'netflix.com', 'apple.com', 'microsoft.com']
    is_typo = 0
    closest_match = "None"
    min_distance = 999
    
    for real_domain in popular_domains:
        distance = Levenshtein.distance(domain, real_domain)
        if distance < min_distance:
            min_distance = distance
            closest_match = real_domain
        if 0 < distance <= 2: 
            is_typo = 1
            
    # Return BOTH the mathematical list for the AI, and a dictionary for Feature A (Forensics)
    feature_vector = [url_len, dot_count, hyphen_count, has_keywords, is_typo, 0] 
    
    forensic_report = {
        "url_length": url_len,
        "dots": dot_count,
        "hyphens": hyphen_count,
        "keyword_triggered": "Yes" if has_keywords == 1 else "No",
        "typosquatting_detected": "Yes" if is_typo == 1 else "No",
        "closest_brand_match": closest_match,
        "edit_distance": min_distance
    }
    
    return feature_vector, forensic_report