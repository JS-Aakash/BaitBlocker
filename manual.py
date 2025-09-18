import requests
import json
import sqlite3
from urllib.parse import urlparse
from feature_extractor import FeatureExtractor
from detector import PhishingDetector
import socket
import re

def is_valid_domain(domain):
    """Check if a domain is valid and can be resolved"""
    try:
        # Extract domain from URL if needed
        if "://" in domain:
            parsed = urlparse(domain)
            domain_to_check = parsed.netloc
        else:
            domain_to_check = domain
        
        # Skip domains with unicode characters that cause issues
        if any(ord(char) > 127 for char in domain_to_check):
            return False
        
        # Try to resolve the domain
        socket.gethostbyname(domain_to_check)
        return True
    except:
        return False

def manual_crawl_and_detect():
    # Known phishing domains for testing
    phishing_domains = [
        "yhaoo.com",
        "micorsoft.com",
        "instagram-reel-ref.web.app",
        "microsoft-security-alert.com",
        "google-account-security.com"
    ]
    
    # Known legitimate domains for testing
    legitimate_domains = [
        "login.amazon.com", 
        "hcase.com",
        "google.co",
        "ctiibank.com",
        "goolge.com"
    ]
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Initialize feature extractor
    extractor = FeatureExtractor()
    
    print("=== Testing Known Phishing Domains ===")
    for domain in phishing_domains:
        print(f"\nProcessing domain: {domain}")
        
        # Check if domain is valid first
        if not is_valid_domain(domain):
            print(f"Domain {domain} is not valid or cannot be resolved")
            continue
        
        # Try to crawl the domain
        urls_to_try = [
            f"https://{domain}",
            f"http://{domain}",
            f"https://www.{domain}",
            f"http://www.{domain}"
        ]
        
        content = None
        url = None
        
        for try_url in urls_to_try:
            try:
                response = requests.get(try_url, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                
                if response.status_code == 200:
                    content = response.text
                    url = try_url
                    print(f"Successfully crawled {domain} at {url}")
                    break
            except requests.RequestException as e:
                print(f"Failed to crawl {try_url}: {e}")
                continue
        
        if content and url:
            # Extract features
            features = extractor.extract_all_features(url, content)
            
            # Make prediction
            prediction, confidence = detector.predict(features)
            
            if prediction is not None:
                status = 'phishing' if prediction == 1 else 'legitimate'
                print(f"Result: {status} (confidence: {confidence:.2f})")
                
                # Check if prediction matches expected
                expected = 'phishing'
                if status == expected:
                    print("✓ Correctly identified as phishing")
                else:
                    print("✗ Incorrectly identified as legitimate")
            else:
                print("Could not make prediction")
        else:
            print(f"Could not crawl {domain}")
    
    print("\n=== Testing Known Legitimate Domains ===")
    for domain in legitimate_domains:
        print(f"\nProcessing domain: {domain}")
        
        # Check if domain is valid first
        if not is_valid_domain(domain):
            print(f"Domain {domain} is not valid or cannot be resolved")
            continue
        
        # Try to crawl the domain
        urls_to_try = [
            f"https://{domain}",
            f"http://{domain}",
            f"https://www.{domain}",
            f"http://www.{domain}"
        ]
        
        content = None
        url = None
        
        for try_url in urls_to_try:
            try:
                response = requests.get(try_url, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                
                if response.status_code == 200:
                    content = response.text
                    url = try_url
                    print(f"Successfully crawled {domain} at {url}")
                    break
            except requests.RequestException as e:
                print(f"Failed to crawl {try_url}: {e}")
                continue
        
        if content and url:
            # Extract features
            features = extractor.extract_all_features(url, content)
            
            # Make prediction
            prediction, confidence = detector.predict(features)
            
            if prediction is not None:
                status = 'phishing' if prediction == 1 else 'legitimate'
                print(f"Result: {status} (confidence: {confidence:.2f})")
                
                # Check if prediction matches expected
                expected = 'legitimate'
                if status == expected:
                    print("✓ Correctly identified as legitimate")
                else:
                    print("✗ Incorrectly identified as phishing")
            else:
                print("Could not make prediction")
        else:
            print(f"Could not crawl {domain}")

if __name__ == "__main__":
    manual_crawl_and_detect()