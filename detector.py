import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import time
import tldextract
import socket
import ssl
import json
import warnings
import math
import string
import colorama
from colorama import Fore, Style
warnings.filterwarnings('ignore')

# Initialize colorama
colorama.init(autoreset=True)

class PhishingDetector:
    def __init__(self, model_path=None, force_retrain=False):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = []
        self.model_path = model_path or 'models/phishing_detector.pkl'
        self.scaler_path = model_path or 'models/scaler.pkl'
        self.force_retrain = force_retrain
        
        # Define the exact feature order that will be used
        self.feature_order = [
            'url_length', 'num_dots', 'repeated_digits', 'special_chars',
            'num_hyphens', 'num_slashes', 'num_underscores', 'num_question_marks',
            'num_equal_signs', 'num_dollar_signs', 'num_exclamation', 'num_hashtags',
            'num_percent_signs', 'domain_length', 'domain_hyphens', 'domain_special_chars',
            'num_subdomains', 'avg_subdomain_length', 'subdomain_complexity',
            'subdomain_hyphen', 'subdomain_repeated_digits', 'path_length',
            'has_query', 'has_fragment', 'has_anchor', 'domain_age_days',
            'name_servers', 'ssl_valid', 'content_length', 'num_links',
            'num_forms', 'num_scripts', 'num_iframes', 'favicon_present',
            'login_keywords_count', 'brand_keywords_count', 'has_password_field',
            'has_hidden_fields', 'has_external_scripts', 'is_error_page',
            'error_page_brand_impersonation', 'error_page_urgent_language',
            'is_established_domain', 'has_privacy_policy', 'has_contact_info',
            'has_terms_of_service', 'domain_reputation_score'
        ]
        
        # List of known legitimate domains and their reputation scores
        self.legitimate_domains = {
            'google.com': 10,
            'microsoft.com': 10,
            'amazon.com': 10,
            'facebook.com': 10,
            'instagram.com': 10,
            'twitter.com': 10,
            'linkedin.com': 10,
            'youtube.com': 10,
            'wikipedia.org': 10,
            'github.com': 9,
            'stackoverflow.com': 9,
            'adobe.com': 9,
            'apple.com': 10,
            'paypal.com': 9,
            'netflix.com': 8,
            'spotify.com': 8,
            'dropbox.com': 8,
            'slack.com': 7,
            'zoom.us': 7,
            'nearbynow.web.app': 8,
            'www.wellsfargo.com': 10,  # Add wellsfargo.com as legitimate
        }
        
        # Common phishing TLDs
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.gq', '.work', '.click', '.download', '.science']
        
        # Suspicious keywords often found in phishing sites
        self.suspicious_keywords = [
            'verify', 'secure', 'login', 'signin', 'account', 'update', 'confirm',
            'urgent', 'immediate', 'limited', 'expire', 'suspend', 'blocked',
            'warning', 'alert', 'security', 'protection', 'safe', 'banking',
            'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
            'instagram', 'twitter', 'linkedin', 'netflix', 'dropbox', 'icloud'
        ]
        
        # Known phishing patterns
        self.phishing_patterns = [
            # Typosquatting patterns
            r'g[o0]{2}gle',  # google, g00gle, g0ogle, etc.
            r'pay[pa]{2}l',  # paypal, paypaal, etc.
            r'am[az]{2}on',  # amazon, amaazon, etc.
            r'm[i1]cr[o0]s[o0]ft',  # microsoft, micr0soft, etc.
            r'f[a4]ce[b6][o0]{2}k',  # facebook, f4ceb00k, etc.
            
            # Subdomain patterns
            r'login\.[^.]+\.(com|net|org)',
            r'secure\.[^.]+\.(com|net|org)',
            r'account\.[^.]+\.(com|net|org)',
            r'verify\.[^.]+\.(com|net|org)',
            r'update\.[^.]+\.(com|net|org)',
            
            # Domain patterns
            r'.*-login\.(com|net|org)',
            r'.*-secure\.(com|net|org)',
            r'.*-account\.(com|net|org)',
            r'.*-verify\.(com|net|org)',
            r'.*-update\.(com|net|org)',
            
            # Error page patterns
            r'.*error.*\.(com|net|org)',
            r'.*verify.*\.(com|net|org)',
            r'.*security.*\.(com|net|org)',
            
            # Suspicious TLD patterns
            r'.*\.(tk|ml|ga|cf|top|gq|work|click|download|science)$',
        ]
        
        # Create models directory if it doesn't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Try to load existing model unless force_retrain is True
        if not self.force_retrain:
            self.load_model()
    
    def prepare_features(self, features_dict):
        """Convert features dictionary to numpy array with proper feature order"""
        # Create a feature vector in the exact order expected by the model
        feature_vector = []
        
        for feature_name in self.feature_order:
            value = features_dict.get(feature_name, 0)
            # Convert boolean to int
            if isinstance(value, bool):
                value = 1 if value else 0
            # Convert None to 0
            elif value is None:
                value = 0
            feature_vector.append(value)
        
        # Create a DataFrame with proper column names
        df = pd.DataFrame([feature_vector], columns=self.feature_order)
        return df
    
    def train(self, training_data_path):
        """Train the phishing detection model with enhanced parameters"""
        try:
            # Load training data
            df = pd.read_csv(training_data_path)
            
            # Separate features and labels
            X = df.drop('label', axis=1)
            y = df['label']
            
            # Store feature columns
            self.feature_columns = X.columns.tolist()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model with enhanced parameters for better phishing detection
            self.model = RandomForestClassifier(
                n_estimators=300,  # Increased number of trees
                max_depth=20,  # Increased depth
                min_samples_split=2,
                min_samples_leaf=1,
                max_features='sqrt',  # Consider sqrt of features at each split
                random_state=42,
                n_jobs=-1,
                class_weight='balanced',  # Handle imbalanced data
                bootstrap=True,
                oob_score=True  # Out-of-bag scoring for better generalization
            )
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            print(f"Model Accuracy: {accuracy:.4f}")
            print(f"Out-of-Bag Score: {self.model.oob_score_:.4f}")
            print(classification_report(y_test, y_pred))
            
            # Feature importance analysis
            feature_importance = pd.DataFrame({
                'feature': self.feature_columns,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            print("\nTop 10 Most Important Features:")
            print(feature_importance.head(10))
            
            # Save model and scaler
            self.save_model()
            
            return accuracy
            
        except Exception as e:
            print(f"Error training model: {e}")
            return None
    
    def create_sample_training_data(self, output_path):
        """Create sample training data for demonstration with more realistic examples"""
        # Define feature columns including the new features
        feature_columns = [
            'url_length', 'num_dots', 'repeated_digits', 'special_chars',
            'num_hyphens', 'num_slashes', 'num_underscores', 'num_question_marks',
            'num_equal_signs', 'num_dollar_signs', 'num_exclamation', 'num_hashtags',
            'num_percent_signs', 'domain_length', 'domain_hyphens', 'domain_special_chars',
            'num_subdomains', 'avg_subdomain_length', 'subdomain_complexity',
            'subdomain_hyphen', 'subdomain_repeated_digits', 'path_length',
            'has_query', 'has_fragment', 'has_anchor', 'domain_age_days',
            'name_servers', 'ssl_valid', 'content_length', 'num_links',
            'num_forms', 'num_scripts', 'num_iframes', 'favicon_present',
            'login_keywords_count', 'brand_keywords_count', 'has_password_field',
            'has_hidden_fields', 'has_external_scripts', 'is_error_page',
            'error_page_brand_impersonation', 'error_page_urgent_language',
            'is_established_domain', 'has_privacy_policy', 'has_contact_info',
            'has_terms_of_service', 'domain_reputation_score'
        ]
        
        # Create legitimate samples (45% of total)
        legitimate_samples = []
        
        # Add specific legitimate samples for known legitimate sites
        legitimate_sites = [
            'google.com', 'microsoft.com', 'amazon.com', 'facebook.com', 
            'instagram.com', 'twitter.com', 'linkedin.com', 'youtube.com',
            'wikipedia.org', 'github.com', 'stackoverflow.com', 'adobe.com',
            'apple.com', 'paypal.com', 'netflix.com', 'spotify.com',
            'dropbox.com', 'slack.com', 'zoom.us', 'nearbynow.web.app', 'wellsfargo.com'
        ]
        
        for site in legitimate_sites:
            sample = {
                'url_length': np.random.randint(15, 25),
                'num_dots': np.random.randint(1, 2),
                'repeated_digits': 0,
                'special_chars': 0,
                'num_hyphens': 0,
                'num_slashes': np.random.randint(1, 2),
                'num_underscores': 0,
                'num_question_marks': 0,
                'num_equal_signs': 0,
                'num_dollar_signs': 0,
                'num_exclamation': 0,
                'num_hashtags': 0,
                'num_percent_signs': 0,
                'domain_length': np.random.randint(10, 20),
                'domain_hyphens': 0,
                'domain_special_chars': 0,
                'num_subdomains': np.random.randint(1, 2),
                'avg_subdomain_length': np.random.randint(2, 6),
                'subdomain_complexity': np.random.uniform(1.0, 2.0),
                'subdomain_hyphen': 0,
                'subdomain_repeated_digits': 0,
                'path_length': np.random.randint(1, 5),
                'has_query': 0,
                'has_fragment': 0,
                'has_anchor': 0,
                'domain_age_days': np.random.randint(1000, 5000),
                'name_servers': np.random.randint(2, 4),
                'ssl_valid': 1,
                'content_length': np.random.randint(5000, 15000),
                'num_links': np.random.randint(50, 150),
                'num_forms': np.random.randint(1, 3),
                'num_scripts': np.random.randint(5, 20),
                'num_iframes': np.random.randint(0, 3),
                'favicon_present': 1,
                'login_keywords_count': np.random.randint(0, 2),
                'brand_keywords_count': np.random.randint(0, 2),
                'has_password_field': np.random.randint(0, 1),
                'has_hidden_fields': np.random.randint(0, 1),
                'has_external_scripts': np.random.randint(0, 1),
                'is_error_page': 0,
                'error_page_brand_impersonation': 0,
                'error_page_urgent_language': 0,
                'is_established_domain': 1,
                'has_privacy_policy': 1,
                'has_contact_info': 1,
                'has_terms_of_service': 1,
                'domain_reputation_score': np.random.randint(8, 10),
                'label': 0  # Legitimate
            }
            legitimate_samples.append(sample)
        
        # Add more generic legitimate samples
        for _ in range(80):
            sample = {
                'url_length': np.random.randint(15, 35),
                'num_dots': np.random.randint(1, 3),
                'repeated_digits': np.random.randint(0, 1),
                'special_chars': np.random.randint(0, 2),
                'num_hyphens': np.random.randint(0, 1),
                'num_slashes': np.random.randint(1, 4),
                'num_underscores': np.random.randint(0, 1),
                'num_question_marks': np.random.randint(0, 1),
                'num_equal_signs': np.random.randint(0, 1),
                'num_dollar_signs': np.random.randint(0, 1),
                'num_exclamation': np.random.randint(0, 1),
                'num_hashtags': np.random.randint(0, 1),
                'num_percent_signs': np.random.randint(0, 1),
                'domain_length': np.random.randint(10, 20),
                'domain_hyphens': np.random.randint(0, 1),
                'domain_special_chars': np.random.randint(0, 1),
                'num_subdomains': np.random.randint(1, 3),
                'avg_subdomain_length': np.random.randint(2, 6),
                'subdomain_complexity': np.random.uniform(1.0, 2.5),
                'subdomain_hyphen': np.random.randint(0, 1),
                'subdomain_repeated_digits': np.random.randint(0, 1),
                'path_length': np.random.randint(1, 15),
                'has_query': np.random.randint(0, 1),
                'has_fragment': np.random.randint(0, 1),
                'has_anchor': np.random.randint(0, 1),
                'domain_age_days': np.random.randint(100, 2000),
                'name_servers': np.random.randint(1, 4),
                'ssl_valid': np.random.randint(0, 1),
                'content_length': np.random.randint(2000, 10000),
                'num_links': np.random.randint(20, 100),
                'num_forms': np.random.randint(1, 3),
                'num_scripts': np.random.randint(3, 15),
                'num_iframes': np.random.randint(0, 3),
                'favicon_present': np.random.randint(0, 1),
                'login_keywords_count': np.random.randint(0, 3),
                'brand_keywords_count': np.random.randint(0, 3),
                'has_password_field': np.random.randint(0, 1),
                'has_hidden_fields': np.random.randint(0, 1),
                'has_external_scripts': np.random.randint(0, 1),
                'is_error_page': np.random.randint(0, 1),
                'error_page_brand_impersonation': np.random.randint(0, 1),
                'error_page_urgent_language': np.random.randint(0, 1),
                'is_established_domain': np.random.randint(0, 1),
                'has_privacy_policy': np.random.randint(0, 1),
                'has_contact_info': np.random.randint(0, 1),
                'has_terms_of_service': np.random.randint(0, 1),
                'domain_reputation_score': np.random.randint(6, 10),
                'label': 0  # Legitimate
            }
            legitimate_samples.append(sample)
        
        # Create phishing samples (55% of total)
        phishing_samples = []
        
        # Add specific phishing samples for known phishing patterns
        phishing_patterns = [
            # Typosquatting
            {'domain': 'g00gle.com', 'brand': 'google', 'type': 'typosquatting'},
            {'domain': 'bank0famerica.com', 'brand': 'bankofamerica', 'type': 'typosquatting'},
            {'domain': 'paypa1.com', 'brand': 'paypal', 'type': 'typosquatting'},
            {'domain': 'amaz0n.com', 'brand': 'amazon', 'type': 'typosquatting'},
            {'domain': 'microsft.com', 'brand': 'microsoft', 'type': 'typosquatting'},
            
            # Adding extra characters
            {'domain': 'facebook-login.com', 'brand': 'facebook', 'type': 'extra_chars'},
            {'domain': 'appleid.verify.com', 'brand': 'apple', 'type': 'extra_chars'},
            {'domain': 'chase-bank.com', 'brand': 'chase', 'type': 'extra_chars'},
            
            # Using different TLDs
            {'domain': 'google.tk', 'brand': 'google', 'type': 'suspicious_tld'},
            {'domain': 'amazon.ml', 'brand': 'amazon', 'type': 'suspicious_tld'},
            {'domain': 'paypal.cf', 'brand': 'paypal', 'type': 'suspicious_tld'},
            
            # Error page phishing
            {'domain': 'instagram-reel-ref.web.app', 'brand': 'instagram', 'type': 'error_page'},
            {'domain': 'facebook-verify.ga', 'brand': 'facebook', 'type': 'error_page'},
            {'domain': 'google-security.ml', 'brand': 'google', 'type': 'error_page'},
            
            # Subdomain phishing
            {'domain': 'login.paypal.com', 'brand': 'paypal', 'type': 'subdomain'},
            {'domain': 'secure.bankofamerica.com', 'brand': 'bankofamerica', 'type': 'subdomain'},
            {'domain': 'account.amazon.com', 'brand': 'amazon', 'type': 'subdomain'},
        ]
        
        for pattern in phishing_patterns:
            sample = {
                'url_length': np.random.randint(30, 60),
                'num_dots': np.random.randint(2, 5),
                'repeated_digits': np.random.randint(1, 3),
                'special_chars': np.random.randint(1, 4),
                'num_hyphens': np.random.randint(0, 3),
                'num_slashes': np.random.randint(2, 6),
                'num_underscores': np.random.randint(0, 2),
                'num_question_marks': np.random.randint(0, 2),
                'num_equal_signs': np.random.randint(0, 2),
                'num_dollar_signs': np.random.randint(0, 2),
                'num_exclamation': np.random.randint(0, 2),
                'num_hashtags': np.random.randint(0, 2),
                'num_percent_signs': np.random.randint(0, 2),
                'domain_length': np.random.randint(15, 40),
                'domain_hyphens': np.random.randint(0, 3),
                'domain_special_chars': np.random.randint(0, 3),
                'num_subdomains': np.random.randint(1, 4),
                'avg_subdomain_length': np.random.randint(4, 12),
                'subdomain_complexity': np.random.uniform(2.0, 4.0),
                'subdomain_hyphen': np.random.randint(0, 1),
                'subdomain_repeated_digits': np.random.randint(0, 1),
                'path_length': np.random.randint(5, 25),
                'has_query': np.random.randint(0, 1),
                'has_fragment': np.random.randint(0, 1),
                'has_anchor': np.random.randint(0, 1),
                'domain_age_days': np.random.randint(1, 60),
                'name_servers': np.random.randint(0, 2),
                'ssl_valid': np.random.randint(0, 1),
                'content_length': np.random.randint(500, 3000),
                'num_links': np.random.randint(5, 30),
                'num_forms': np.random.randint(1, 5),
                'num_scripts': np.random.randint(5, 20),
                'num_iframes': np.random.randint(1, 6),
                'favicon_present': np.random.randint(0, 1),
                'login_keywords_count': np.random.randint(2, 8),
                'brand_keywords_count': np.random.randint(2, 8),
                'has_password_field': np.random.randint(0, 1),
                'has_hidden_fields': np.random.randint(0, 1),
                'has_external_scripts': np.random.randint(0, 1),
                'is_error_page': 1 if pattern['type'] == 'error_page' else 0,
                'error_page_brand_impersonation': 3 if pattern['type'] == 'error_page' else 0,
                'error_page_urgent_language': 4 if pattern['type'] == 'error_page' else 0,
                'is_established_domain': 0,
                'has_privacy_policy': np.random.randint(0, 1),
                'has_contact_info': np.random.randint(0, 1),
                'has_terms_of_service': np.random.randint(0, 1),
                'domain_reputation_score': np.random.randint(0, 4),
                'label': 1  # Phishing
            }
            phishing_samples.append(sample)
        
        # Add more generic phishing samples
        for _ in range(100):
            sample = {
                'url_length': np.random.randint(35, 80),
                'num_dots': np.random.randint(3, 8),
                'repeated_digits': np.random.randint(1, 5),
                'special_chars': np.random.randint(2, 8),
                'num_hyphens': np.random.randint(1, 5),
                'num_slashes': np.random.randint(3, 10),
                'num_underscores': np.random.randint(1, 5),
                'num_question_marks': np.random.randint(1, 4),
                'num_equal_signs': np.random.randint(1, 4),
                'num_dollar_signs': np.random.randint(1, 4),
                'num_exclamation': np.random.randint(1, 4),
                'num_hashtags': np.random.randint(0, 3),
                'num_percent_signs': np.random.randint(1, 4),
                'domain_length': np.random.randint(20, 50),
                'domain_hyphens': np.random.randint(1, 5),
                'domain_special_chars': np.random.randint(1, 5),
                'num_subdomains': np.random.randint(2, 6),
                'avg_subdomain_length': np.random.randint(6, 15),
                'subdomain_complexity': np.random.uniform(2.5, 5.0),
                'subdomain_hyphen': np.random.randint(0, 1),
                'subdomain_repeated_digits': np.random.randint(0, 1),
                'path_length': np.random.randint(15, 40),
                'has_query': np.random.randint(0, 1),
                'has_fragment': np.random.randint(0, 1),
                'has_anchor': np.random.randint(0, 1),
                'domain_age_days': np.random.randint(1, 30),
                'name_servers': np.random.randint(0, 2),
                'ssl_valid': np.random.randint(0, 1),
                'content_length': np.random.randint(500, 3000),
                'num_links': np.random.randint(5, 30),
                'num_forms': np.random.randint(1, 5),
                'num_scripts': np.random.randint(5, 20),
                'num_iframes': np.random.randint(1, 6),
                'favicon_present': np.random.randint(0, 1),
                'login_keywords_count': np.random.randint(2, 8),
                'brand_keywords_count': np.random.randint(2, 8),
                'has_password_field': np.random.randint(0, 1),
                'has_hidden_fields': np.random.randint(0, 1),
                'has_external_scripts': np.random.randint(0, 1),
                'is_error_page': np.random.randint(0, 1),
                'error_page_brand_impersonation': np.random.randint(0, 3),
                'error_page_urgent_language': np.random.randint(0, 5),
                'is_established_domain': 0,
                'has_privacy_policy': np.random.randint(0, 1),
                'has_contact_info': np.random.randint(0, 1),
                'has_terms_of_service': np.random.randint(0, 1),
                'domain_reputation_score': np.random.randint(0, 5),
                'label': 1  # Phishing
            }
            phishing_samples.append(sample)
        
        # Combine all samples
        all_samples = legitimate_samples + phishing_samples
        
        # Create DataFrame with columns in the correct order
        df = pd.DataFrame(all_samples)
        
        # Reorder columns to match our expected order
        df = df[['label'] + self.feature_order]
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save to CSV
        df.to_csv(output_path, index=False)
        print(f"Sample training data created at {output_path}")
        print(f"Created {len(all_samples)} samples ({len(legitimate_samples)} legitimate, {len(phishing_samples)} phishing)")
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        entropy = 0
        for char in set(text):
            p = text.count(char) / len(text)
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def is_ip_address(self, host):
        """Check if the host is an IP address"""
        try:
            socket.inet_aton(host)
            return True
        except socket.error:
            return False
    
    def extract_additional_features(self, url, content):
        """Extract additional features for phishing detection"""
        features = {}
        
        # Parse URL
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path
        
        # 1. IP address in URL
        features['ip_in_url'] = 1 if self.is_ip_address(host) else 0
        
        # 2. @ in URL
        features['at_in_url'] = 1 if '@' in url else 0
        
        # 3. Punycode in URL
        features['punycode_in_url'] = 1 if 'xn--' in host else 0
        
        # 4. Typosquatting score
        features['typosquatting_score'] = 0
        cse_brands = ['google', 'microsoft', 'amazon', 'facebook', 'instagram', 'twitter', 'linkedin', 'youtube', 'paypal', 'bankofamerica', 'chase', 'citibank', 'wellsfargo', 'adobe', 'apple']
        for brand in cse_brands:
            if self.is_typosquatting(host, brand):
                features['typosquatting_score'] = 0.8
                break
        
        # 5. Domain entropy
        features['domain_entropy'] = self.calculate_entropy(host)
        
        # 6. Path entropy
        features['path_entropy'] = self.calculate_entropy(path)
        
        # 7. Number of redirects (if available)
        features['num_redirects'] = 0
        
        # 8. Meta refresh
        features['has_meta_refresh'] = 1 if 'meta http-equiv="refresh"' in content.lower() else 0
        
        # 9. Form action external
        features['form_action_external'] = 0
        if 'action=' in content.lower():
            soup = BeautifulSoup(content, 'html.parser')
            for form in soup.find_all('form', action=True):
                action = form.get('action', '')
                if action and urlparse(action).netloc != host:
                    features['form_action_external'] = 1
                    break
        
        # 10. Obfuscated JS
        features['has_obfuscated_js'] = 0
        if 'eval(' in content or 'btoa(' in content or 'atob(' in content or 'String.fromCharCode(' in content:
            features['has_obfuscated_js'] = 1
        
        # 11. Certificate features (if available)
        features['cert_validity_days'] = 0
        features['cert_cn_mismatch'] = 0
        
        # 12. Mixed content detection
        features['has_mixed_content'] = 0
        if 'https://' in url and 'http://' in content:
            features['has_mixed_content'] = 1
        
        return features
    
    def predict(self, features_dict):
        """Predict if a domain is phishing with enhanced rule-based logic"""
        if self.model is None:
            print("Model not trained. Please train the model first.")
            return None, 0.0, None
        
        try:
            # Get the domain for additional checks
            domain = features_dict.get('domain', '')
            url = features_dict.get('url', f'https://{domain}')
            content = features_dict.get('content', '')
            
            # Extract additional features
            additional_features = self.extract_additional_features(url, content)
            features_dict.update(additional_features)
            
            # Prepare features with proper column order
            features_df = self.prepare_features(features_dict)
            
            # Scale features
            features_scaled = self.scaler.transform(features_df)
            
            # Make model prediction
            model_prediction = self.model.predict(features_scaled)[0]
            model_confidence = self.model.predict_proba(features_scaled)[0].max()
            
            # Apply rule-based adjustments
            phishing_score = 0
            reasons = []
            matched_brand = None
            
            # URL & domain features
            if features_dict.get('ip_in_url', 0) == 1:
                phishing_score += 0.3
                reasons.append("IP address in URL")
            
            if features_dict.get('url_length', 0) > 100:
                phishing_score += 0.2
                reasons.append("Unusually long URL")
            
            if features_dict.get('at_in_url', 0) == 1:
                phishing_score += 0.4
                reasons.append("@ symbol in URL")
            
            if features_dict.get('num_dots', 0) > 5:
                phishing_score += 0.2
                reasons.append("Too many dots in URL")
            
            if features_dict.get('num_hyphens', 0) > 3:
                phishing_score += 0.2
                reasons.append("Too many hyphens in URL")
            
            if features_dict.get('num_subdomains', 0) > 3:
                phishing_score += 0.3
                reasons.append("Multiple subdomains")
            
            if features_dict.get('punycode_in_url', 0) == 1:
                phishing_score += 0.4
                reasons.append("Punycode/Internationalized domain name")
            
            if features_dict.get('typosquatting_score', 0) > 0.7:
                phishing_score += 0.5
                reasons.append("Typosquatting detected")
                
                # Find which brand is being typosquatted
                cse_brands = ['google', 'microsoft', 'amazon', 'facebook', 'instagram', 'twitter', 'linkedin', 'youtube', 'paypal', 'bankofamerica', 'chase', 'citibank', 'wellsfargo', 'adobe', 'apple']
                for brand in cse_brands:
                    if self.is_typosquatting(domain, brand):
                        matched_brand = brand
                        break
            
            if features_dict.get('domain_entropy', 0) > 4.0:
                phishing_score += 0.3
                reasons.append("High domain entropy")
            
            # TLS / certificate features
            if features_dict.get('ssl_valid', 0) == 0:
                phishing_score += 0.3
                reasons.append("No TLS/HTTP only")
            
            if features_dict.get('cert_cn_mismatch', 0) == 1:
                phishing_score += 0.4
                reasons.append("Certificate CN/SAN mismatch")
            
            if features_dict.get('cert_validity_days', 0) < 30:
                phishing_score += 0.3
                reasons.append("Short certificate validity")
            
            # Domain age & registration
            if features_dict.get('domain_age_days', 365) < 30:
                phishing_score += 0.3
                reasons.append("Newly registered domain")
            
            # HTTP & headers
            if features_dict.get('num_redirects', 0) > 2:
                phishing_score += 0.3
                reasons.append("Multiple redirects")
            
            if features_dict.get('has_meta_refresh', 0) == 1:
                phishing_score += 0.4
                reasons.append("Meta refresh redirect")
            
            # Forms & data flow
            if features_dict.get('has_password_field', 0) == 1:
                phishing_score += 0.2
                reasons.append("Password field present")
            
            if features_dict.get('form_action_external', 0) == 1:
                phishing_score += 0.5
                reasons.append("Form action posts to different domain")
            
            if features_dict.get('has_hidden_fields', 0) == 1:
                phishing_score += 0.3
                reasons.append("Hidden form fields")
            
            # Page content
            if features_dict.get('brand_keywords_count', 0) > 3:
                phishing_score += 0.3
                reasons.append("Multiple brand keywords")
            
            if features_dict.get('login_keywords_count', 0) > 3:
                phishing_score += 0.3
                reasons.append("Multiple login keywords")
            
            if features_dict.get('error_page_urgent_language', 0) > 2:
                phishing_score += 0.4
                reasons.append("Urgent language")
            
            # JavaScript & runtime behavior
            if features_dict.get('has_obfuscated_js', 0) == 1:
                phishing_score += 0.3
                reasons.append("Obfuscated JavaScript")
            
            if features_dict.get('has_external_scripts', 0) == 1 and features_dict.get('num_iframes', 0) > 0:
                phishing_score += 0.3
                reasons.append("External scripts and iframes")
            
            # Mixed content detection
            if features_dict.get('has_mixed_content', 0) == 1:
                phishing_score += 0.4
                reasons.append("Mixed content (HTTPS with HTTP resources)")
            
            # Check for redirects to legitimate sites
            is_redirect, original_domain, final_domain = self.check_phishing_redirect(url)
            if is_redirect and final_domain in self.legitimate_domains:
                phishing_score += 0.6
                reasons.append(f"Redirecting to legitimate site: {final_domain}")
            
            # Check if domain is a legitimate CSE domain
            if domain in self.legitimate_domains:
                phishing_score -= 0.5
                reasons.append(f"Domain is a legitimate CSE domain: {domain}")
            
            # Determine final prediction
            if phishing_score >= 1.0:
                # High confidence phishing
                prediction = 1
                confidence = max(model_confidence, 0.9)
            elif phishing_score >= 0.7:
                # Likely phishing
                prediction = 1
                confidence = max(model_confidence, 0.8)
            elif phishing_score >= 0.4:
                # Possible phishing
                if model_prediction == 0:
                    # Model says legitimate but rules suggest phishing
                    prediction = 1
                    confidence = max(model_confidence, 0.7)
                else:
                    # Model already says phishing
                    prediction = 1
                    confidence = max(model_confidence, 0.7)
            else:
                # Likely legitimate
                if model_prediction == 1:
                    # Model says phishing but rules don't strongly suggest it
                    prediction = 0
                    confidence = 1 - model_confidence  # Reverse confidence
                else:
                    # Both model and rules say legitimate
                    prediction = 0
                    confidence = max(model_confidence, 0.8)
            
            return prediction, confidence, matched_brand
            
        except Exception as e:
            print(f"Error making prediction: {e}")
            return None, 0.0, None
    
    def is_typosquatting(self, domain, brand):
        """Check if a domain is a typosquatting of a brand"""
        domain_lower = domain.lower()
        brand_lower = brand.lower()
        
        # Direct typosquatting patterns
        typosquatting_patterns = [
            # Character substitution
            brand_lower.replace('a', '4'),
            brand_lower.replace('a', '@'),
            brand_lower.replace('e', '3'),
            brand_lower.replace('i', '1'),
            brand_lower.replace('i', '!'),
            brand_lower.replace('o', '0'),
            brand_lower.replace('s', '5'),
            brand_lower.replace('s', '$'),
            brand_lower.replace('t', '7'),
            brand_lower.replace('z', '2'),
            
            # Character omission
            brand_lower[1:] if len(brand_lower) > 1 else brand_lower,
            brand_lower[:-1] if len(brand_lower) > 1 else brand_lower,
            
            # Character duplication
            brand_lower[0] + brand_lower,
            brand_lower + brand_lower[-1],
            
            # Character transposition
            ''.join(brand_lower[i] + brand_lower[i+1] + brand_lower[i] + brand_lower[i+2:] 
                    for i in range(len(brand_lower)-1)),
        ]
        
        # Check if domain matches any of the typosquatting patterns
        for pattern in typosquatting_patterns:
            if domain_lower.startswith(pattern):
                return True
        
        return False
    
    def check_phishing_redirect(self, url):
        """Check if a URL is a phishing redirect"""
        try:
            # Create a session with redirect tracking
            session = requests.Session()
            session.max_redirects = 5  # Limit redirects to prevent infinite loops
            
            # Set headers to mimic a real browser
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            
            # Make the request
            response = session.get(url, timeout=10, allow_redirects=True, verify=False)
            
            # Check if there were redirects
            if len(response.history) > 0:
                # Get the final URL after all redirects
                final_url = response.url
                
                # Extract domains from original and final URLs
                original_domain = urlparse(url).netloc
                final_domain = urlparse(final_url).netloc
                
                # If the domain changed, it's a redirect
                if original_domain != final_domain:
                    # Check if the final domain is a known legitimate domain
                    if final_domain in self.legitimate_domains:
                        # This is a phishing site redirecting to a legitimate site
                        return True, original_domain, final_domain
                    else:
                        # This might be a legitimate redirect or another phishing site
                        return False, original_domain, final_domain
            
            return False, url, url
            
        except Exception as e:
            print(f"Error checking for redirect: {e}")
            return False, url, url
    
    def check_domain_manually(self, domain):
        """Manually check a domain for phishing with detailed analysis"""
        print(f"\n=== Manual Phishing Check for {domain} ===")
        
        # Initialize result
        result = {
            'domain': domain,
            'is_phishing': False,
            'confidence': 0.0,
            'indicators': [],
            'matched_brand': None
        }
        
        # 1. Check if domain can be resolved
        try:
            socket.gethostbyname(domain)
            print(f"✓ Domain can be resolved")
        except socket.gaierror:
            print(f"✗ Domain cannot be resolved")
            result['indicators'].append("Domain cannot be resolved")
            return result
        
        # 2. Check if domain is a legitimate CSE domain
        if domain in self.legitimate_domains:
            print(f"✓ Domain is a legitimate CSE domain: {domain}")
            result['indicators'].append(f"Legitimate CSE domain: {domain}")
            result['is_phishing'] = False
            result['confidence'] = 0.1
            return result
        
        # 3. Check for suspicious TLDs
        if any(tld in domain for tld in self.suspicious_tlds):
            print(f"✓ Suspicious TLD detected")
            result['indicators'].append("Suspicious TLD")
            result['is_phishing'] = True
            result['confidence'] += 0.3
        
        # 4. Check for brand impersonation
        domain_lower = domain.lower()
        cse_brands = ['google', 'microsoft', 'amazon', 'facebook', 'instagram', 'twitter', 'linkedin', 'youtube', 'paypal', 'bankofamerica', 'chase', 'citibank', 'wellsfargo', 'adobe', 'apple']
        
        contains_brand = any(brand in domain_lower for brand in cse_brands)
        is_actual_brand = domain in self.legitimate_domains
        
        if contains_brand and not is_actual_brand:
            print(f"✓ Brand impersonation detected")
            result['indicators'].append("Brand impersonation")
            result['is_phishing'] = True
            result['confidence'] += 0.4
        
        # 5. Check for typosquatting
        for brand in cse_brands:
            if self.is_typosquatting(domain, brand):
                print(f"✓ Typosquatting detected for brand: {brand}")
                result['indicators'].append(f"Typosquatting of {brand}")
                result['matched_brand'] = brand
                result['is_phishing'] = True
                result['confidence'] += 0.5
                break
        
        # 6. Check for suspicious subdomains
        suspicious_subdomains = ['login', 'secure', 'signin', 'account', 'verify', 'update', 'confirm']
        domain_parts = domain.split('.')
        if any(sub in domain_parts for sub in suspicious_subdomains):
            print(f"✓ Suspicious subdomain detected")
            result['indicators'].append("Suspicious subdomain")
            result['is_phishing'] = True
            result['confidence'] += 0.3
        
        # 7. Check for suspicious keywords in domain
        if any(keyword in domain_lower for keyword in self.suspicious_keywords):
            print(f"✓ Suspicious keywords detected")
            result['indicators'].append("Suspicious keywords")
            result['is_phishing'] = True
            result['confidence'] += 0.2
        
        # 8. Check for phishing patterns using regex
        for pattern in self.phishing_patterns:
            if re.match(pattern, domain_lower):
                print(f"✓ Phishing pattern detected: {pattern}")
                result['indicators'].append(f"Phishing pattern: {pattern}")
                result['is_phishing'] = True
                result['confidence'] += 0.5
                break
        
        # 9. Try to crawl the domain
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            
            # Try HTTPS first
            url = f"https://{domain}"
            response = session.get(url, timeout=10, verify=False)
            
            print(f"✓ Successfully crawled {url} (Status: {response.status_code})")
            
            # Check for redirects
            if len(response.history) > 0:
                final_url = response.url
                original_domain = urlparse(url).netloc
                final_domain = urlparse(final_url).netloc
                
                if original_domain != final_domain:
                    print(f"✓ Redirect detected: {original_domain} -> {final_domain}")
                    result['indicators'].append(f"Redirect to {final_domain}")
                    
                    # Check if redirecting to a legitimate site
                    if final_domain in self.legitimate_domains:
                        print(f"✓ Redirecting to legitimate site: {final_domain}")
                        result['indicators'].append(f"Redirecting to legitimate site {final_domain}")
                        result['is_phishing'] = True
                        result['confidence'] += 0.6
            
            # Analyze content
            content = response.text.lower()
            
            # Check for mixed content
            if 'https://' in url and 'http://' in content:
                print(f"✓ Mixed content detected (HTTPS with HTTP resources)")
                result['indicators'].append("Mixed content")
                result['is_phishing'] = True
                result['confidence'] += 0.4
            
            # Check for login forms
            if 'type="password"' in content:
                print(f"✓ Password field detected")
                result['indicators'].append("Password field")
                result['is_phishing'] = True
                result['confidence'] += 0.2
            
            # Check for brand keywords in content
            brand_keywords_count = sum(1 for brand in cse_brands if brand in content)
            if brand_keywords_count > 2:
                print(f"✓ Multiple brand keywords detected ({brand_keywords_count})")
                result['indicators'].append(f"Multiple brand keywords ({brand_keywords_count})")
                result['is_phishing'] = True
                result['confidence'] += 0.3
            
            # Check for urgent language
            urgent_keywords = ['urgent', 'immediately', 'limited time', 'expire', 'suspend', 'blocked']
            urgent_count = sum(1 for keyword in urgent_keywords if keyword in content)
            if urgent_count > 0:
                print(f"✓ Urgent language detected ({urgent_count} instances)")
                result['indicators'].append(f"Urgent language ({urgent_count} instances)")
                result['is_phishing'] = True
                result['confidence'] += 0.2
            
            # Check for external scripts and iframes (potential for hidden redirects)
            if content.count('<script src=') > 3 and content.count('<iframe') > 0:
                print(f"✓ Multiple external scripts and iframes detected")
                result['indicators'].append("Multiple external scripts and iframes")
                result['is_phishing'] = True
                result['confidence'] += 0.2
            
            # Check for meta refresh redirects
            if 'meta http-equiv="refresh"' in content:
                print(f"✓ Meta refresh redirect detected")
                result['indicators'].append("Meta refresh redirect")
                result['is_phishing'] = True
                result['confidence'] += 0.4
            
            # Check for JavaScript redirects
            if 'window.location' in content or 'document.location' in content:
                print(f"✓ JavaScript redirect detected")
                result['indicators'].append("JavaScript redirect")
                result['is_phishing'] = True
                result['confidence'] += 0.4
            
            # Check for suspicious form actions
            if 'action=' in content and any(brand in content for brand in cse_brands):
                print(f"✓ Suspicious form action detected")
                result['indicators'].append("Suspicious form action")
                result['is_phishing'] = True
                result['confidence'] += 0.3
            
        except Exception as e:
            print(f"✗ Error crawling domain: {e}")
            result['indicators'].append(f"Error crawling: {str(e)}")
        
        # Cap confidence at 1.0
        result['confidence'] = min(result['confidence'], 1.0)
        
        # Print final result
        print(f"\n=== Result ===")
        print(f"Domain: {domain}")
        print(f"Is Phishing: {result['is_phishing']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Indicators: {', '.join(result['indicators'])}")
        if result['matched_brand']:
            print(f"Resembles CSE brand: {result['matched_brand']}")
        
        return result
    
    def save_model(self):
        """Save the trained model and scaler"""
        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            print(f"Model saved to {self.model_path}")
        except Exception as e:
            print(f"Error saving model: {e}")
    
    def load_model(self):
        """Load the trained model and scaler"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                print(f"Model loaded from {self.model_path}")
                return True
        except Exception as e:
            print(f"Error loading model: {e}")
        
        return False