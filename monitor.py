import time
import threading
import schedule
from datetime import datetime, timedelta
import sqlite3

class DomainMonitor:
    def __init__(self, detector, db, config):
        self.detector = detector
        self.db = db
        self.config = config
        self.running = False
        self.monitor_thread = None
    
    def start(self):
        """Start the monitoring system"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        print("Domain monitoring started")
        
        # Schedule regular checks
        schedule.every().day.at("02:00").do(self._scheduled_check)
    
    def stop(self):
        """Stop the monitoring system"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print("Domain monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    def _scheduled_check(self):
        """Scheduled check for all domains"""
        print(f"Running scheduled check at {datetime.now()}")
        domains_to_check = self.db.get_domains_to_check()
        
        for domain in domains_to_check:
            self._check_domain(domain)
    
    def add_domain(self, domain, duration_days=90):
        """Add a domain to monitoring"""
        self.db.add_suspected_domain(domain, duration_days)
        print(f"Added {domain} to monitoring for {duration_days} days")
    
    def _check_domain(self, domain):
        """Check a specific domain"""
        try:
            print(f"Checking domain: {domain}")
            
            # Crawl the domain
            from crawler import simple_crawl_domain
            url, status_code, content, headers = simple_crawl_domain(domain, self.db)
            
            if url and content:
                # Extract features
                from feature_extractor import FeatureExtractor
                extractor = FeatureExtractor()
                features = extractor.extract_all_features(url, content)
                
                # Make prediction
                prediction, confidence = self.detector.predict(features)
                
                if prediction is not None:
                    # Update database
                    if prediction == 1:  # Phishing
                        self.db.update_domain_status(domain, 'phishing', confidence, features)
                        self.db.add_alert(domain, 'phishing_detected', 
                                        f"Phishing detected with confidence {confidence:.2f}")
                        print(f"PHISHING DETECTED: {domain} (confidence: {confidence:.2f})")
                    else:
                        self.db.update_domain_status(domain, 'legitimate', confidence, features)
                        print(f"Legitimate: {domain} (confidence: {confidence:.2f})")
                else:
                    print(f"Could not make prediction for {domain}")
            else:
                print(f"Could not crawl {domain}")
                
        except Exception as e:
            print(f"Error checking domain {domain}: {e}")
    
    def get_status(self):
        """Get monitoring status"""
        return {
            'running': self.running,
            'total_domains': len(self.db.get_domains_to_check()),
            'phishing_domains': len(self.db.get_phishing_domains())
        }