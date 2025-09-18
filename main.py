import os
import sys
import argparse
from datetime import datetime, timedelta
import sqlite3
import time
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup
import re
import colorama
from colorama import Fore, Style
import webbrowser

# Initialize colorama
colorama.init(autoreset=True)

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import *
from database import PhishingDatabase
from seed_generator import SeedGenerator
from detector import PhishingDetector
from monitor import DomainMonitor
from reporter import ReportGenerator
from crawler import batch_crawl_domains

def setup_environment():
    """Setup the environment and create necessary directories"""
    print("Setting up environment...")
    
    # Create directories
    for dir_path in OUTPUT_CONFIG.values():
        os.makedirs(dir_path, exist_ok=True)
    
    # Initialize database
    db = PhishingDatabase(DATABASE_PATH)
    print(f"Database initialized at {DATABASE_PATH}")
    
    return db

def train_model(args):
    """Train the phishing detection model"""
    print("Training phishing detection model...")
    
    # Initialize detector with force retrain option
    force_retrain = getattr(args, 'force_retrain', False)
    detector = PhishingDetector(force_retrain=force_retrain)
    
    # Check if training data exists, create sample if not
    training_data_path = args.training_data or 'data/training_data.csv'
    if not os.path.exists(training_data_path):
        print(f"Training data not found at {training_data_path}")
        print("Creating sample training data...")
        detector.create_sample_training_data(training_data_path)
    
    # Train model
    accuracy = detector.train(training_data_path)
    if accuracy:
        print(f"Model trained successfully with accuracy: {accuracy:.4f}")
    else:
        print("Model training failed")
    
    return detector

def crawl_domains(args, db):
    """Crawl domains and extract features"""
    print("Crawling domains...")
    
    # Generate seeds
    seed_generator = SeedGenerator('data/cse_domains.txt')
    seeds = seed_generator.generate_seeds(args.max_seeds)
    print(f"Generated {len(seeds)} valid seed URLs")
    
    # Simple crawling (for demonstration)
    from crawler import simple_crawl_domain
    from feature_extractor import FeatureExtractor
    
    extractor = FeatureExtractor()
    results = []
    successful_crawls = 0
    
    for i, domain in enumerate(seeds[:args.max_domains]):
        print(f"Crawling {i+1}/{min(len(seeds), args.max_domains)}: {domain}")
        
        url, status_code, content, headers = simple_crawl_domain(domain, db)
        
        if url and content:
            features = extractor.extract_all_features(url, content)
            results.append({
                'domain': domain,
                'url': url,
                'status_code': status_code,
                'features': features
            })
            successful_crawls += 1
    
    print(f"Crawled {successful_crawls}/{len(seeds[:args.max_domains])} domains successfully")
    return results

def recrawl_domains(args, db):
    """Recrawl domains that don't have crawl results"""
    print("Recrawling domains without results...")
    
    # Get all domains that don't have crawl results
    domains = db.get_domains_without_results()
    
    if not domains:
        print("No domains need recrawling")
        return
    
    print(f"Recrawling {len(domains)} domains...")
    
    # Simple crawling
    from crawler import simple_crawl_domain
    from feature_extractor import FeatureExtractor
    
    extractor = FeatureExtractor()
    results = []
    successful_crawls = 0
    
    for i, domain in enumerate(domains[:args.max_domains]):
        print(f"Recrawling {i+1}/{min(len(domains), args.max_domains)}: {domain}")
        
        url, status_code, content, headers = simple_crawl_domain(domain, db)
        
        if url and content:
            features = extractor.extract_all_features(url, content)
            results.append({
                'domain': domain,
                'url': url,
                'status_code': status_code,
                'features': features
            })
            successful_crawls += 1
    
    print(f"Recrawled {successful_crawls}/{len(domains[:args.max_domains])} domains successfully")
    return results

def detect_phishing(args, db, detector):
    """Detect phishing domains"""
    print("Detecting phishing domains...")
    
    # Get domains to analyze
    if args.domains:
        domains = args.domains.split(',')
    else:
        # Get suspected domains from database
        domains = db.get_domains_to_check()
    
    if not domains:
        print("No domains to analyze")
        return []
    
    print(f"Analyzing {len(domains)} domains...")
    
    results = []
    
    for domain in domains:
        print(f"Analyzing: {domain}")
        
        # Get crawl results
        crawl_results = db.get_crawl_results(domain)
        
        if crawl_results:
            url, status_code, content, headers, crawled_at = crawl_results[0]
            
            # Skip if content is an error message
            if content in ["Invalid domain format", "Unresolvable domain", "All URLs failed", "SSL error", "Timeout error", "Connection error", "Request error"]:
                print(f"  Skipping {domain} due to crawl error: {content}")
                continue
            
            # Extract features
            from feature_extractor import FeatureExtractor
            extractor = FeatureExtractor()
            features = extractor.extract_all_features(url, content)
            
            # Check for redirects
            is_redirect, original_url, final_url = detector.check_phishing_redirect(url)
            
            # Make prediction
            prediction, confidence, matched_brand = detector.predict(features)
            
            # Override prediction if it's a phishing redirect
            if is_redirect:
                prediction = 1  # Phishing
                confidence = max(confidence, 0.9)  # High confidence for redirects
            
            if prediction is not None:
                status = 'phishing' if prediction == 1 else 'legitimate'
                
                # Update database
                db.update_domain_status(domain, status, confidence, features)
                
                results.append({
                    'domain': domain,
                    'status': status,
                    'confidence': confidence,
                    'url': url,
                    'date': crawled_at,
                    'features': features,
                    'matched_brand': matched_brand
                })
                
                print(f"  Result: {status} (confidence: {confidence:.2f})")
                if matched_brand:
                    print(f"  Resembles CSE brand: {matched_brand}")
                
                # Print additional info if it's a redirect
                if is_redirect:
                    print(f"  Redirect detected: {original_url} -> {final_url}")
            else:
                print("  Could not make prediction")
        else:
            print(f"  No crawl results found for {domain}")
    
    return results

def add_and_detect(args, db, detector):
    """Add a specific domain and immediately detect if it's phishing"""
    domain = args.domain
    print(f"Adding and analyzing domain: {domain}")
    
    # Add domain to database
    db.add_suspected_domain(domain, 90)
    
    # Crawl the domain
    from crawler import simple_crawl_domain
    from feature_extractor import FeatureExtractor
    
    url, status_code, content, headers = simple_crawl_domain(domain, db)
    
    if url and content:
        # Extract features
        extractor = FeatureExtractor()
        features = extractor.extract_all_features(url, content)
        
        # Make prediction
        prediction, confidence, matched_brand = detector.predict(features)
        
        if prediction is not None:
            status = 'phishing' if prediction == 1 else 'legitimate'
            
            # Update database
            db.update_domain_status(domain, status, confidence, features)
            
            print(f"Result: {status} (confidence: {confidence:.2f})")
            if matched_brand:
                print(f"Resembles CSE brand: {matched_brand}")
            
            return {
                'domain': domain,
                'status': status,
                'confidence': confidence,
                'url': url,
                'features': features,
                'matched_brand': matched_brand
            }
        else:
            print("Could not make prediction")
    else:
        print(f"Could not crawl {domain}")
    
    return None

def check_domain(args, db, detector):
    """Check a specific domain for phishing with detailed analysis"""
    domain = args.domain
    
    # Check if domain is in CSE domains list
    try:
        with open('data/cse_domains.txt', 'r') as f:
            cse_domains = [line.strip() for line in f if line.strip()]
        if domain in cse_domains:
            print(f"Domain {domain} is in CSE domains list. Skipping check.")
            return None
    except FileNotFoundError:
        pass
    
    # Check if domain is already in database
    all_domains = db.get_all_domains()
    existing_domains = [d[0] for d in all_domains]
    if domain in existing_domains:
        print(f"Domain {domain} is already in database. Skipping check.")
        return None
    
    print(f"Checking domain: {domain}")
    
    # Use the enhanced manual check
    result = detector.check_domain_manually(domain)
    
    # If domain was successfully crawled, also use the model prediction
    try:
        # Crawl the domain
        from crawler import simple_crawl_domain
        from feature_extractor import FeatureExtractor
        
        url, status_code, content, headers = simple_crawl_domain(domain, db)
        
        if url and content:
            # Extract features
            extractor = FeatureExtractor()
            features = extractor.extract_all_features(url, content)
            
            # Make prediction with the model
            model_prediction, model_confidence, model_matched_brand = detector.predict(features)
            
            if model_prediction is not None:
                model_status = 'phishing' if model_prediction == 1 else 'legitimate'
                print(f"\n=== Model Prediction ===")
                print(f"Model Prediction: {model_status}")
                print(f"Model Confidence: {model_confidence:.2f}")
                if model_matched_brand:
                    print(f"Model Detected Brand: {model_matched_brand}")
                
                # Compare with manual check
                if model_status != ('phishing' if result['is_phishing'] else 'legitimate'):
                    print(f"⚠️  Manual check and model prediction differ")
                
                # Use the manual check result as it's more reliable for phishing detection
                # But if the model is more confident, use the model result
                if model_confidence > result['confidence']:
                    result['is_phishing'] = model_prediction == 1
                    result['confidence'] = model_confidence
                    if model_matched_brand:
                        result['matched_brand'] = model_matched_brand
    except Exception as e:
        print(f"Error using model prediction: {e}")
    
    # Print final result
    print(f"\n=== Final Result ===")
    print(f"Domain: {domain}")
    print(f"Is Phishing: {result['is_phishing']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Indicators: {', '.join(result['indicators'])}")
    if result['matched_brand']:
        print(f"Resembles CSE brand: {result['matched_brand']}")
    
    return result

def generate_report(args, results):
    """Generate submission report"""
    if not results:
        print("No results to report")
        return
    
    print("Generating report...")
    
    # Initialize reporter
    reporter = ReportGenerator(OUTPUT_CONFIG['reports_dir'])
    
    # Generate submission
    application_id = args.application_id or f"DEMO_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    zip_path = reporter.generate_submission(application_id, results)
    
    print(f"Report generated: {zip_path}")
    return zip_path

def start_monitoring(args, db, detector):
    """Start continuous monitoring"""
    print("Starting monitoring system...")
    
    # Initialize monitor
    monitor = DomainMonitor(detector, db, MONITOR_CONFIG)
    
    # Add domains to monitor
    if args.domains:
        domains = args.domains.split(',')
        for domain in domains:
            monitor.add_domain(domain, args.duration)
    else:
        # Add suspected domains from database
        domains = db.get_domains_to_check()
        for domain in domains:
            monitor.add_domain(domain, args.duration)
    
    # Start monitoring
    monitor.start()
    
    try:
        print("Monitoring started. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping monitoring...")
        monitor.stop()

def mark_domains_suspected(args, db):
    """Mark recently crawled domains as suspected for analysis"""
    print("Marking domains as suspected...")
    
    # Get all domains from database
    domains = db.get_all_domains()
    
    # Mark domains as suspected
    marked_count = 0
    for domain, status in domains:
        if status != 'suspected':
            db.add_suspected_domain(domain, 90)  # Monitor for 90 days
            print(f"Marked {domain} as suspected")
            marked_count += 1
    
    print(f"Marked {marked_count} domains as suspected")

def list_domains(args, db):
    """List all domains in the database"""
    print("Listing all domains in database...")
    
    domains = db.get_all_domains()
    
    for domain in domains:
        print(f"Domain: {domain[0]}, Status: {domain[1]}")
    
    print(f"Total domains: {len(domains)}")

def cleanup_database(args, db):
    """Clean up the database"""
    confirm = input("Are you sure you want to clean up the database? This will reset all domains to 'unknown' status and delete all crawl results. (y/n): ")
    if confirm.lower() == 'y':
        db.cleanup_database()
    else:
        print("Database cleanup cancelled")

def delete_database(args, db):
    """Delete the entire database file"""
    confirm = input("Are you sure you want to delete the entire database? This action cannot be undone. (y/n): ")
    if confirm.lower() == 'y':
        db.delete_database()
    else:
        print("Database deletion cancelled")

def delete_model(args):
    """Delete the model files to force retraining"""
    model_path = 'models/phishing_detector.pkl'
    scaler_path = 'models/scaler.pkl'
    
    confirm = input("Are you sure you want to delete the model files? This will force retraining. (y/n): ")
    if confirm.lower() == 'y':
        if os.path.exists(model_path):
            os.remove(model_path)
            print(f"Deleted model file: {model_path}")
        if os.path.exists(scaler_path):
            os.remove(scaler_path)
            print(f"Deleted scaler file: {scaler_path}")
    else:
        print("Model deletion cancelled")

# New functions for CSE phishing detection
def crawl_cse_domains(args, db):
    """Crawl CSE domains and their variations for phishing detection"""
    print("Crawling CSE domains for phishing detection...")
    
    # Load CSE domains
    cse_domains_file = args.cse_domains or 'data/cse_domains.txt'
    
    # Generate seeds
    seed_generator = SeedGenerator(cse_domains_file)
    seeds = seed_generator.generate_seeds(args.max_seeds)
    print(f"Generated {len(seeds)} seed URLs")
    
    # Crawl domains in batches
    batch_size = args.batch_size or 10
    max_workers = args.max_workers or 3
    
    all_results = []
    successful_crawls = 0
    
    # Process domains in batches
    for i in range(0, len(seeds), batch_size):
        batch = seeds[i:i+batch_size]
        print(f"\nProcessing batch {i//batch_size + 1}/{(len(seeds) + batch_size - 1) // batch_size} ({len(batch)} domains)")
        
        # Crawl batch
        batch_results = batch_crawl_domains(batch, db, max_workers=max_workers)
        
        # Process results
        for domain, (url, status_code, content, headers) in batch_results.items():
            if url and content:
                print(f"  ✓ Successfully crawled: {domain}")
                all_results.append({
                    'domain': domain,
                    'url': url,
                    'status_code': status_code,
                    'content': content,
                    'headers': headers
                })
                successful_crawls += 1
            else:
                print(f"  ✗ Failed to crawl: {domain}")
    
    print(f"\nCrawling complete. Successfully crawled {successful_crawls}/{len(seeds)} domains.")
    
    return all_results

def detect_cse_phishing(args, db, detector):
    """Detect phishing among CSE domains with enhanced logic"""
    print("Detecting phishing among CSE domains...")
    
    # Get suspected domains from database
    with sqlite3.connect(db.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT domain FROM domains 
            WHERE status = 'suspected' 
            AND (suspected_until > CURRENT_TIMESTAMP OR suspected_until IS NULL)
        ''')
        domains = [row[0] for row in cursor.fetchall()]
    
    if not domains:
        print("No suspected domains to analyze")
        
        # Let's check what domains are in the database
        with sqlite3.connect(db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT domain, status, suspected_until FROM domains')
            all_domains = cursor.fetchall()
            print(f"\nAll domains in database:")
            for domain, status, suspected_until in all_domains:
                print(f"  Domain: {domain}, Status: {status}, Suspected until: {suspected_until}")
        
        # Check if there are domains that need to be marked as suspected
        with sqlite3.connect(db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT domain FROM domains 
                WHERE status != 'suspected' OR suspected_until IS NULL OR suspected_until <= CURRENT_TIMESTAMP
            ''')
            domains_to_mark = [row[0] for row in cursor.fetchall()]
            
            if domains_to_mark:
                print(f"\nFound {len(domains_to_mark)} domains that need to be marked as suspected")
                for domain in domains_to_mark:
                    db.add_suspected_domain(domain, 90)
                    print(f"  Marked {domain} as suspected")
                
                # Now try to detect again
                cursor.execute('''
                    SELECT domain FROM domains 
                    WHERE status = 'suspected' 
                    AND (suspected_until > CURRENT_TIMESTAMP OR suspected_until IS NULL)
                ''')
                domains = [row[0] for row in cursor.fetchall()]
                
                if domains:
                    print(f"\nNow analyzing {len(domains)} suspected domains...")
                else:
                    print("\nStill no suspected domains to analyze after marking")
                    return []
            else:
                print("\nNo domains need to be marked as suspected")
                return []
    
    print(f"Analyzing {len(domains)} suspected domains...")
    
    results = []
    
    for i, domain in enumerate(domains):
        # Make the domain clickable in the console
        clickable_domain = f"\n{Fore.CYAN}{domain}{Style.RESET_ALL}"
        print(f"{clickable_domain} ({i+1}/{len(domains)})")
        
        # Get crawl results
        crawl_results = db.get_crawl_results(domain)
        
        if crawl_results:
            url, status_code, content, headers, crawled_at = crawl_results[0]
            
            # Skip if content is an error message
            if content in ["Invalid domain format", "Unresolvable domain", "All URLs failed", "SSL error", "Timeout error", "Connection error", "Request error"]:
                print(f"  Skipping {domain} due to crawl error: {content}")
                continue
            
            # Extract features
            from feature_extractor import FeatureExtractor
            extractor = FeatureExtractor()
            features = extractor.extract_all_features(url, content)
            
            # Check for redirects
            is_redirect, original_url, final_url = detector.check_phishing_redirect(url)
            
            # Make prediction
            prediction, confidence, matched_brand = detector.predict(features)
            
            # Override prediction if it's a phishing redirect
            if is_redirect:
                prediction = 1  # Phishing
                confidence = max(confidence, 0.9)  # High confidence for redirects
            
            if prediction is not None:
                status = 'phishing' if prediction == 1 else 'legitimate'
                
                # Update database
                db.update_domain_status(domain, status, confidence, features)
                
                results.append({
                    'domain': domain,
                    'status': status,
                    'confidence': confidence,
                    'url': url,
                    'date': crawled_at,
                    'features': features,
                    'matched_brand': matched_brand
                })
                
                # Color code the result
                if status == 'phishing':
                    status_text = f"{Fore.RED}{status}{Style.RESET_ALL}"
                else:
                    status_text = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
                
                print(f"  Result: {status_text} (confidence: {confidence:.2f})")
                
                if matched_brand:
                    print(f"  Resembles CSE brand: {matched_brand}")
                
                # Print additional info if it's a redirect
                if is_redirect:
                    print(f"  Redirect detected: {original_url} -> {final_url}")
            else:
                print("  Could not make prediction")
        else:
            print(f"  No crawl results found for {domain}")
    
    # Print summary
    if results:
        phishing_count = sum(1 for r in results if r['status'] == 'phishing')
        legitimate_count = sum(1 for r in results if r['status'] == 'legitimate')
        print(f"\nSummary: {len(results)} domains analyzed, {phishing_count} phishing detected, {legitimate_count} legitimate")
    else:
        print("\nNo domains could be analyzed due to crawl errors")
    
    return results

def recheck_domains(args, db, detector):
    """Recheck already marked sites"""
    print("Rechecking already marked sites...")
    
    # Get all domains from database
    with sqlite3.connect(db.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT domain, status FROM domains')
        all_domains = cursor.fetchall()
    
    if not all_domains:
        print("No domains found in database")
        return []
    
    print(f"Rechecking {len(all_domains)} domains...")
    
    results = []
    
    for i, (domain, current_status) in enumerate(all_domains):
        # Make the domain clickable in the console
        clickable_domain = f"\n{Fore.CYAN}{domain}{Style.RESET_ALL}"
        print(f"{clickable_domain} ({i+1}/{len(all_domains)}) - Current status: {current_status}")
        
        # Get crawl results
        crawl_results = db.get_crawl_results(domain)
        
        if crawl_results:
            url, status_code, content, headers, crawled_at = crawl_results[0]
            
            # Skip if content is an error message
            if content in ["Invalid domain format", "Unresolvable domain", "All URLs failed", "SSL error", "Timeout error", "Connection error", "Request error"]:
                print(f"  Skipping {domain} due to crawl error: {content}")
                continue
            
            # Extract features
            from feature_extractor import FeatureExtractor
            extractor = FeatureExtractor()
            features = extractor.extract_all_features(url, content)
            
            # Check for redirects
            is_redirect, original_url, final_url = detector.check_phishing_redirect(url)
            
            # Make prediction
            prediction, confidence, matched_brand = detector.predict(features)
            
            # Override prediction if it's a phishing redirect
            if is_redirect:
                prediction = 1  # Phishing
                confidence = max(confidence, 0.9)  # High confidence for redirects
            
            if prediction is not None:
                status = 'phishing' if prediction == 1 else 'legitimate'
                
                # Update database
                db.update_domain_status(domain, status, confidence, features)
                
                results.append({
                    'domain': domain,
                    'status': status,
                    'confidence': confidence,
                    'url': url,
                    'date': crawled_at,
                    'features': features,
                    'matched_brand': matched_brand,
                    'previous_status': current_status
                })
                
                # Color code the result
                if status == 'phishing':
                    status_text = f"{Fore.RED}{status}{Style.RESET_ALL}"
                else:
                    status_text = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
                
                # Check if status changed
                if status != current_status:
                    change_text = f"{Fore.YELLOW}(Changed from {current_status}){Style.RESET_ALL}"
                else:
                    change_text = ""
                
                print(f"  Result: {status_text} (confidence: {confidence:.2f}) {change_text}")
                
                if matched_brand:
                    print(f"  Resembles CSE brand: {matched_brand}")
                
                # Print additional info if it's a redirect
                if is_redirect:
                    print(f"  Redirect detected: {original_url} -> {final_url}")
            else:
                print("  Could not make prediction")
        else:
            print(f"  No crawl results found for {domain}")
    
    # Print summary
    if results:
        phishing_count = sum(1 for r in results if r['status'] == 'phishing')
        legitimate_count = sum(1 for r in results if r['status'] == 'legitimate')
        changed_count = sum(1 for r in results if r.get('previous_status') != r['status'])
        print(f"\nSummary: {len(results)} domains rechecked, {phishing_count} phishing detected, {legitimate_count} legitimate, {changed_count} status changes")
    else:
        print("\nNo domains could be analyzed due to crawl errors")
    
    return results

def check_new_domains(args, db, detector):
    """Check only new domains that haven't been checked yet"""
    print("Checking new domains that haven't been checked yet...")
    
    # Get all domains from database
    with sqlite3.connect(db.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT domain FROM domains')
        existing_domains = set(row[0] for row in cursor.fetchall())
    
    # Generate new seeds
    seed_generator = SeedGenerator('data/cse_domains.txt')
    all_seeds = seed_generator.generate_seeds(100)  # Generate a large number of seeds
    
    # Filter out existing domains
    new_seeds = [domain for domain in all_seeds if domain not in existing_domains]
    
    if not new_seeds:
        print("No new domains to check")
        return []
    
    print(f"Found {len(new_seeds)} new domains to check")
    
    # Limit to a reasonable number
    max_domains = args.max_domains or 20
    domains_to_check = new_seeds[:max_domains]
    
    print(f"Checking {len(domains_to_check)} new domains...")
    
    results = []
    
    for i, domain in enumerate(domains_to_check):
        # Make the domain clickable in the console
        clickable_domain = f"\n{Fore.CYAN}{domain}{Style.RESET_ALL}"
        print(f"{clickable_domain} ({i+1}/{len(domains_to_check)})")
        
        # Add domain to database
        db.add_suspected_domain(domain, 90)
        
        # Crawl the domain
        from crawler import simple_crawl_domain
        from feature_extractor import FeatureExtractor
        
        url, status_code, content, headers = simple_crawl_domain(domain, db)
        
        if url and content:
            # Extract features
            extractor = FeatureExtractor()
            features = extractor.extract_all_features(url, content)
            
            # Check for redirects
            is_redirect, original_url, final_url = detector.check_phishing_redirect(url)
            
            # Make prediction
            prediction, confidence, matched_brand = detector.predict(features)
            
            # Override prediction if it's a phishing redirect
            if is_redirect:
                prediction = 1  # Phishing
                confidence = max(confidence, 0.9)  # High confidence for redirects
            
            if prediction is not None:
                status = 'phishing' if prediction == 1 else 'legitimate'
                
                # Update database
                db.update_domain_status(domain, status, confidence, features)
                
                results.append({
                    'domain': domain,
                    'status': status,
                    'confidence': confidence,
                    'url': url,
                    'features': features,
                    'matched_brand': matched_brand
                })
                
                # Color code the result
                if status == 'phishing':
                    status_text = f"{Fore.RED}{status}{Style.RESET_ALL}"
                else:
                    status_text = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
                
                print(f"  Result: {status_text} (confidence: {confidence:.2f})")
                
                if matched_brand:
                    print(f"  Resembles CSE brand: {matched_brand}")
                
                # Print additional info if it's a redirect
                if is_redirect:
                    print(f"  Redirect detected: {original_url} -> {final_url}")
            else:
                print("  Could not make prediction")
        else:
            print(f"  Could not crawl {domain}")
    
    # Print summary
    if results:
        phishing_count = sum(1 for r in results if r['status'] == 'phishing')
        legitimate_count = sum(1 for r in results if r['status'] == 'legitimate')
        print(f"\nSummary: {len(results)} new domains checked, {phishing_count} phishing detected, {legitimate_count} legitimate")
    else:
        print("\nNo new domains could be analyzed due to crawl errors")
    
    return results

def generate_cse_report(args, db):
    """Generate a report of CSE phishing detection results"""
    print("Generating CSE phishing detection report...")
    
    # Get phishing domains from database
    phishing_domains = db.get_phishing_domains()
    
    # Get legitimate domains from database
    legitimate_domains = db.get_legitimate_domains()
    
    # Get suspected domains from database
    suspected_domains = db.get_suspected_domains()
    
    # Prepare results
    results = []
    
    # Add phishing domains
    for domain, confidence, created_at in phishing_domains:
        results.append({
            'domain': domain,
            'status': 'phishing',
            'confidence': confidence,
            'date': created_at
        })
    
    # Add legitimate domains
    for domain, confidence, created_at in legitimate_domains:
        results.append({
            'domain': domain,
            'status': 'legitimate',
            'confidence': confidence,
            'date': created_at
        })
    
    # Add suspected domains
    for domain, created_at in suspected_domains:
        results.append({
            'domain': domain,
            'status': 'suspected',
            'confidence': 0.0,
            'date': created_at
        })
    
    if not results:
        print("No results to report")
        return None
    
    # Generate report
    reporter = ReportGenerator(OUTPUT_CONFIG['reports_dir'])
    
    # Generate submission
    application_id = args.application_id or f"CSE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    zip_path = reporter.generate_submission(application_id, results)
    
    print(f"Report generated: {zip_path}")
    return zip_path

def open_domain(args):
    """Open a domain in the default web browser"""
    domain = args.domain
    
    # Ensure the URL has a protocol
    if not domain.startswith(('http://', 'https://')):
        url = f"https://{domain}"
    else:
        url = domain
    
    print(f"Opening {url} in the default web browser...")
    webbrowser.open(url)

def main():
    parser = argparse.ArgumentParser(description='Phishing Domain Detection System')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train the phishing detection model')
    train_parser.add_argument('--training-data', help='Path to training data CSV file')
    train_parser.add_argument('--force-retrain', action='store_true', help='Force retraining even if model exists')
    
    # Crawl command
    crawl_parser = subparsers.add_parser('crawl', help='Crawl domains and extract features')
    crawl_parser.add_argument('--max-seeds', type=int, default=100, help='Maximum number of seed URLs to generate')
    crawl_parser.add_argument('--max-domains', type=int, default=20, help='Maximum number of domains to crawl')
    
    # Recrawl command
    recrawl_parser = subparsers.add_parser('recrawl', help='Recrawl domains without results')
    recrawl_parser.add_argument('--max-domains', type=int, default=20, help='Maximum number of domains to recrawl')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect phishing domains')
    detect_parser.add_argument('--domains', help='Comma-separated list of domains to analyze')
    
    # Add and detect command
    add_detect_parser = subparsers.add_parser('add-detect', help='Add a specific domain and detect if phishing')
    add_detect_parser.add_argument('--domain', required=True, help='Domain to add and analyze')
    
    # Check domain command
    check_parser = subparsers.add_parser('check-domain', help='Check a specific domain for phishing with detailed analysis')
    check_parser.add_argument('--domain', required=True, help='Domain to check')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate submission report')
    report_parser.add_argument('--application-id', help='Application ID for the report')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start continuous monitoring')
    monitor_parser.add_argument('--domains', help='Comma-separated list of domains to monitor')
    monitor_parser.add_argument('--duration', type=int, default=90, help='Monitoring duration in days')
    
    # Mark suspected command
    mark_parser = subparsers.add_parser('mark-suspected', help='Mark recently crawled domains as suspected for analysis')
    
    # List domains command
    list_parser = subparsers.add_parser('list-domains', help='List all domains in the database')
    
    # Cleanup database command
    cleanup_parser = subparsers.add_parser('cleanup-db', help='Clean up the database (reset status and delete results)')
    
    # Delete database command
    delete_parser = subparsers.add_parser('delete-db', help='Delete the entire database file')
    
    # Delete model command
    delete_model_parser = subparsers.add_parser('delete-model', help='Delete model files to force retraining')
    
    # Open domain command
    open_parser = subparsers.add_parser('open-domain', help='Open a domain in the default web browser')
    open_parser.add_argument('--domain', required=True, help='Domain to open')
    
    # New CSE commands
    # Crawl CSE command
    crawl_cse_parser = subparsers.add_parser('crawl-cse', help='Crawl CSE domains and their variations')
    crawl_cse_parser.add_argument('--cse-domains', help='Path to CSE domains file')
    crawl_cse_parser.add_argument('--max-seeds', type=int, default=100, help='Maximum number of seed URLs to generate')
    crawl_cse_parser.add_argument('--batch-size', type=int, default=10, help='Number of domains to crawl in each batch')
    crawl_cse_parser.add_argument('--max-workers', type=int, default=3, help='Maximum number of parallel workers')
    
    # Detect CSE phishing command
    detect_cse_parser = subparsers.add_parser('detect-cse', help='Detect phishing among CSE domains')
    
    # Recheck domains command
    recheck_parser = subparsers.add_parser('recheck-domains', help='Recheck already marked sites')
    
    # Check new domains command
    check_new_parser = subparsers.add_parser('check-new-domains', help='Check only new domains that haven\'t been checked yet')
    check_new_parser.add_argument('--max-domains', type=int, default=20, help='Maximum number of new domains to check')
    
    # Generate CSE report command
    report_cse_parser = subparsers.add_parser('report-cse', help='Generate CSE phishing detection report')
    report_cse_parser.add_argument('--application-id', help='Application ID for the report')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup environment
    db = setup_environment()
    
    try:
        if args.command == 'train':
            detector = train_model(args)
        
        elif args.command == 'crawl':
            results = crawl_domains(args, db)
        
        elif args.command == 'recrawl':
            results = recrawl_domains(args, db)
        
        elif args.command == 'detect':
            # Initialize detector
            detector = PhishingDetector()
            if not detector.model:
                print("Model not found. Please train the model first using 'train' command.")
                return
            
            results = detect_phishing(args, db, detector)
            
            # Print summary
            if results:
                phishing_count = sum(1 for r in results if r['status'] == 'phishing')
                print(f"\nSummary: {len(results)} domains analyzed, {phishing_count} phishing detected")
        
        elif args.command == 'add-detect':
            # Initialize detector
            detector = PhishingDetector()
            if not detector.model:
                print("Model not found. Please train the model first using 'train' command.")
                return
            
            result = add_and_detect(args, db, detector)
        
        elif args.command == 'check-domain':
            # Initialize detector
            detector = PhishingDetector()
            if not detector.model:
                print("Model not found. Please train the model first using 'train' command.")
                return
            
            result = check_domain(args, db, detector)
        
        elif args.command == 'report':
            # Get results from database
            phishing_domains = db.get_phishing_domains()
            results = []
            for domain, confidence, created_at in phishing_domains:
                results.append({
                    'domain': domain,
                    'status': 'phishing',
                    'confidence': confidence,
                    'date': created_at
                })
            
            generate_report(args, results)
        
        elif args.command == 'monitor':
            # Initialize detector
            detector = PhishingDetector()
            if not detector.model:
                print("Model not found. Please train the model first using 'train' command.")
                return
            
            start_monitoring(args, db, detector)
        
        elif args.command == 'mark-suspected':
            mark_domains_suspected(args, db)
        
        elif args.command == 'list-domains':
            list_domains(args, db)
        
        elif args.command == 'cleanup-db':
            cleanup_database(args, db)
        
        elif args.command == 'delete-db':
            delete_database(args, db)
        
        elif args.command == 'delete-model':
            delete_model(args)
        
        elif args.command == 'open-domain':
            open_domain(args)
        
        # New CSE commands
        elif args.command == 'crawl-cse':
            results = crawl_cse_domains(args, db)
        
        elif args.command == 'detect-cse':
            # Initialize detector
            detector = PhishingDetector()
            if not detector.model:
                print("Model not found. Please train the model first using 'train' command.")
                return
            
            results = detect_cse_phishing(args, db, detector)
        
        elif args.command == 'recheck-domains':
            # Initialize detector
            detector = PhishingDetector()
            if not detector.model:
                print("Model not found. Please train the model first using 'train' command.")
                return
            
            results = recheck_domains(args, db, detector)
        
        elif args.command == 'check-new-domains':
            # Initialize detector
            detector = PhishingDetector()
            if not detector.model:
                print("Model not found. Please train the model first using 'train' command.")
                return
            
            results = check_new_domains(args, db, detector)
        
        elif args.command == 'report-cse':
            zip_path = generate_cse_report(args, db)
            if zip_path:
                print(f"Report generated at: {zip_path}")
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()