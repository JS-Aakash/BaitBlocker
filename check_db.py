import sqlite3

def check_database():
    # Connect to database
    conn = sqlite3.connect('data/phishing_detector.db')
    cursor = conn.cursor()
    
    # Check domains table
    print("=== DOMAINS TABLE ===")
    cursor.execute('SELECT * FROM domains')
    domains = cursor.fetchall()
    
    for domain in domains:
        print(f"ID: {domain[0]}, Domain: {domain[1]}, Status: {domain[2]}")
    
    print(f"\nTotal domains: {len(domains)}")
    
    # Check crawl_results table
    print("\n=== CRAWL RESULTS TABLE ===")
    cursor.execute('SELECT cr.domain_id, d.domain, cr.url, cr.status_code FROM crawl_results cr JOIN domains d ON cr.domain_id = d.id')
    crawl_results = cursor.fetchall()
    
    for result in crawl_results:
        print(f"Domain ID: {result[0]}, Domain: {result[1]}, URL: {result[2]}, Status: {result[3]}")
    
    print(f"\nTotal crawl results: {len(crawl_results)}")
    
    # Check suspected domains
    print("\n=== SUSPECTED DOMAINS ===")
    cursor.execute('SELECT domain FROM domains WHERE status = "suspected"')
    suspected = cursor.fetchall()
    
    for domain in suspected:
        print(f"Domain: {domain[0]}")
    
    print(f"\nTotal suspected domains: {len(suspected)}")
    
    conn.close()

if __name__ == "__main__":
    check_database()