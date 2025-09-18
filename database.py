import sqlite3
import json
from datetime import datetime, timedelta
import os

class PhishingDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE,
                    status TEXT DEFAULT 'unknown',
                    confidence_score REAL DEFAULT 0.0,
                    features TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    suspected_until TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crawl_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    url TEXT,
                    status_code INTEGER,
                    content TEXT,
                    headers TEXT,
                    crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (domain_id) REFERENCES domains (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    alert_type TEXT,
                    message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (domain_id) REFERENCES domains (id)
                )
            ''')
            
            conn.commit()
    
    def add_domain(self, domain, status='unknown'):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                # First, try to insert
                cursor.execute('''
                    INSERT OR IGNORE INTO domains (domain, status)
                    VALUES (?, ?)
                ''', (domain, status))
                conn.commit()
                
                # Get the domain ID (whether it was inserted or already exists)
                cursor.execute('SELECT id FROM domains WHERE domain = ?', (domain,))
                result = cursor.fetchone()
                if result:
                    return result[0]
                else:
                    # If still not found, try to insert again
                    cursor.execute('''
                        INSERT INTO domains (domain, status)
                        VALUES (?, ?)
                    ''', (domain, status))
                    conn.commit()
                    return cursor.lastrowid
            except sqlite3.Error as e:
                print(f"Database error: {e}")
                return None
    
    def update_domain_status(self, domain, status, confidence_score=0.0, features=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            features_json = json.dumps(features) if features else None
            cursor.execute('''
                UPDATE domains 
                SET status = ?, confidence_score = ?, features = ?, last_checked = CURRENT_TIMESTAMP
                WHERE domain = ?
            ''', (status, confidence_score, features_json, domain))
            conn.commit()
    
    def add_suspected_domain(self, domain, duration_days=90):
        suspected_until = datetime.now() + timedelta(days=duration_days)
        suspected_until_str = suspected_until.strftime('%Y-%m-%d %H:%M:%S')
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # First, try to update if the domain exists
            cursor.execute('''
                UPDATE domains 
                SET status = 'suspected', suspected_until = ?
                WHERE domain = ?
            ''', (suspected_until_str, domain))
            
            # If no rows were updated, then insert
            if cursor.rowcount == 0:
                cursor.execute('''
                    INSERT INTO domains (domain, status, suspected_until)
                    VALUES (?, 'suspected', ?)
                ''', (domain, suspected_until_str))
            
            conn.commit()
    
    def get_domains_to_check(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT domain FROM domains 
                WHERE status = 'suspected' 
                AND (suspected_until > CURRENT_TIMESTAMP OR suspected_until IS NULL)
            ''')
            domains = [row[0] for row in cursor.fetchall()]
            print(f"Found {len(domains)} suspected domains to check")
            return domains
    
    def get_suspected_domains(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT domain, created_at FROM domains 
                WHERE status = 'suspected' 
                AND suspected_until > CURRENT_TIMESTAMP
            ''')
            return cursor.fetchall()
    
    def get_phishing_domains(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT domain, confidence_score, created_at FROM domains 
                WHERE status = 'phishing'
                ORDER BY confidence_score DESC
            ''')
            return cursor.fetchall()
    
    def get_legitimate_domains(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT domain, confidence_score, created_at FROM domains 
                WHERE status = 'legitimate'
                ORDER BY confidence_score DESC
            ''')
            return cursor.fetchall()
    
    def get_all_domains(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT domain, status, suspected_until FROM domains
            ''')
            return cursor.fetchall()
    
    def get_domains_without_results(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT d.domain FROM domains d
                LEFT JOIN crawl_results cr ON d.id = cr.domain_id
                WHERE cr.id IS NULL
            ''')
            return [row[0] for row in cursor.fetchall()]
    
    def get_crawl_results(self, domain):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT cr.url, cr.status_code, cr.content, cr.headers, cr.crawled_at
                FROM crawl_results cr
                JOIN domains d ON cr.domain_id = d.id
                WHERE d.domain = ?
                ORDER BY cr.crawled_at DESC
            ''', (domain,))
            return cursor.fetchall()
    
    def add_alert(self, domain, alert_type, message):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (domain_id, alert_type, message)
                VALUES ((SELECT id FROM domains WHERE domain = ?), ?, ?)
            ''', (domain, alert_type, message))
            conn.commit()
    
    def cleanup_database(self):
        """Clean up the database (reset status and delete results)"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Reset all domains to 'unknown' status
            cursor.execute('''
                UPDATE domains
                SET status = 'unknown', confidence_score = 0.0, features = NULL
            ''')
            
            # Delete all crawl results
            cursor.execute('DELETE FROM crawl_results')
            
            # Delete all alerts
            cursor.execute('DELETE FROM alerts')
            
            conn.commit()
            
            print("Database cleaned up")
    
    def delete_database(self):
        """Delete the entire database file"""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            print(f"Database file deleted: {self.db_path}")
        else:
            print("Database file not found")
    
    def get_domain_id(self, domain):
        """Get the ID of a domain by name"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM domains WHERE domain = ?', (domain,))
            result = cursor.fetchone()
            return result[0] if result else None