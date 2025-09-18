import requests
from urllib.parse import urlparse
import json
import sqlite3
from database import PhishingDatabase
from feature_extractor import FeatureExtractor
from detector import PhishingDetector
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Disable SSL warnings
warnings.filterwarnings("ignore", category=Warning)

def create_robust_session():
    """Create a robust requests session with retry strategy for phishing sites"""
    session = requests.Session()
    
    # Set retry strategy with correct parameter names for newer urllib3 versions
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    
    # Mount HTTP and HTTPS adapters with retry strategy
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set headers that mimic a real browser
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
    })
    
    # Disable SSL verification
    session.verify = False
    
    # Set timeout
    session.timeout = 15
    
    return session

def crawl_phishing_sites():
    """Crawl and analyze known phishing sites"""
    
    # List of known phishing sites to test
    phishing_sites = [
        "https://instagram-reel-ref.web.app",
        "https://nearbynow.web.app",
        "https://amazon-reward-survey.com",
        "https://apple-security-warning.com",
        "https://paypal-verify-account.com"
    ]
    
    # List of legitimate sites for comparison
    legitimate_sites = [
        "https://google.com",
        "https://microsoft.com",
        "https://amazon.com",
        "https://facebook.com",
        "https://instagram.com"
    ]
    
    # Initialize database
    db = PhishingDatabase('data/phishing_detector.db')
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Initialize feature extractor
    extractor = FeatureExtractor()
    
    # Create a robust session
    session = create_robust_session()
    
    results = []
    
    print("=== Testing Phishing Sites ===")
    for url in phishing_sites:
        print(f"\nProcessing: {url}")
        
        try:
            # Extract domain from URL
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Add domain to database
            domain_id = db.add_domain(domain, 'suspected')
            
            # Try to crawl the URL
            response = session.get(url)
            
            print(f"Status code: {response.status_code}")
            
            # Store the crawl result
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO crawl_results (domain_id, url, status_code, content, headers)
                    VALUES (?, ?, ?, ?, ?)
                ''', (domain_id, url, response.status_code, response.text, json.dumps(dict(response.headers))))
                conn.commit()
            
            # Extract features and make prediction if status code is 200
            if response.status_code == 200:
                print(f"Successfully crawled {url}")
                
                # Extract features
                features = extractor.extract_all_features(url, response.text)
                
                # Make prediction
                prediction, confidence = detector.predict(features)
                
                if prediction is not None:
                    status = 'phishing' if prediction == 1 else 'legitimate'
                    
                    # Update database
                    db.update_domain_status(domain, status, confidence, features)
                    
                    print(f"Result: {status} (confidence: {confidence:.2f})")
                    
                    results.append({
                        'domain': domain,
                        'url': url,
                        'status': status,
                        'confidence': confidence,
                        'features': features
                    })
                else:
                    print("Could not make prediction")
            else:
                print(f"Failed to crawl {url}, status code: {response.status_code}")
                
                # Even if we get a 404, we can still analyze the response
                if response.text:
                    # Extract features
                    features = extractor.extract_all_features(url, response.text)
                    
                    # Make prediction
                    prediction, confidence = detector.predict(features)
                    
                    if prediction is not None:
                        status = 'phishing' if prediction == 1 else 'legitimate'
                        
                        # Update database
                        db.update_domain_status(domain, status, confidence, features)
                        
                        print(f"Result (from error page): {status} (confidence: {confidence:.2f})")
                        
                        results.append({
                            'domain': domain,
                            'url': url,
                            'status': status,
                            'confidence': confidence,
                            'features': features
                        })
                
        except Exception as e:
            print(f"Error processing {url}: {e}")
    
    print("\n=== Testing Legitimate Sites ===")
    for url in legitimate_sites:
        print(f"\nProcessing: {url}")
        
        try:
            # Extract domain from URL
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Add domain to database
            domain_id = db.add_domain(domain, 'suspected')
            
            # Try to crawl the URL
            response = session.get(url)
            
            print(f"Status code: {response.status_code}")
            
            # Store the crawl result
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO crawl_results (domain_id, url, status_code, content, headers)
                    VALUES (?, ?, ?, ?, ?)
                ''', (domain_id, url, response.status_code, response.text, json.dumps(dict(response.headers))))
                conn.commit()
            
            # Extract features and make prediction if status code is 200
            if response.status_code == 200:
                print(f"Successfully crawled {url}")
                
                # Extract features
                features = extractor.extract_all_features(url, response.text)
                
                # Make prediction
                prediction, confidence = detector.predict(features)
                
                if prediction is not None:
                    status = 'phishing' if prediction == 1 else 'legitimate'
                    
                    # Update database
                    db.update_domain_status(domain, status, confidence, features)
                    
                    print(f"Result: {status} (confidence: {confidence:.2f})")
                    
                    results.append({
                        'domain': domain,
                        'url': url,
                        'status': status,
                        'confidence': confidence,
                        'features': features
                    })
                else:
                    print("Could not make prediction")
            else:
                print(f"Failed to crawl {url}, status code: {response.status_code}")
                
        except Exception as e:
            print(f"Error processing {url}: {e}")
    
    # Print summary
    print("\n=== SUMMARY ===")
    print(f"Processed {len(phishing_sites) + len(legitimate_sites)} domains")
    print(f"Successfully analyzed {len(results)} domains")
    
    phishing_count = sum(1 for r in results if r['status'] == 'phishing')
    legitimate_count = sum(1 for r in results if r['status'] == 'legitimate')
    
    print(f"Phishing domains: {phishing_count}")
    print(f"Legitimate domains: {legitimate_count}")
    
    # Print detailed results
    print("\n=== DETAILED RESULTS ===")
    for result in results:
        print(f"{result['domain']}: {result['status']} (confidence: {result['confidence']:.2f})")
    
    return results

if __name__ == "__main__":
    crawl_phishing_sites()