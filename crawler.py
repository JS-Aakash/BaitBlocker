import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings
from twisted.internet import reactor, defer
from scrapy.crawler import CrawlerRunner
from scrapy.utils.log import configure_logging
import tldextract
import json
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import time
import sqlite3
import ssl
import re
import socket
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import concurrent.futures
from datetime import datetime
import string

class TimeoutException(Exception):
    pass

class PhishingSpider(scrapy.Spider):
    name = "phishing_detector"
    
    def __init__(self, seeds, db, *args, **kwargs):
        super(PhishingSpider, self).__init__(*args, **kwargs)
        self.start_urls = seeds
        self.db = db
        self.allowed_domains = [self.extract_domain(url) for url in seeds]
        self.visited_urls = set()
        self.timeout = 10  # Reduced timeout to 10 seconds
        self.max_depth = 1  # Limit crawl depth to prevent getting stuck
    
    def extract_domain(self, url):
        try:
            return tldextract.extract(url).registered_domain
        except:
            return urlparse(url).netloc
    
    def start_requests(self):
        for url in self.start_urls:
            domain_id = self.db.add_domain(self.extract_domain(url))
            yield scrapy.Request(url, callback=self.parse, meta={'domain_id': domain_id, 'depth': 0}, 
                               errback=self.errback_handler, dont_filter=True, timeout=self.timeout)
    
    def parse(self, response):
        # Check if we've exceeded max depth
        depth = response.meta.get('depth', 0)
        if depth >= self.max_depth:
            return
        
        if response.url in self.visited_urls:
            return
        
        self.visited_urls.add(response.url)
        domain_id = response.meta.get('domain_id')
        
        # Store crawl results
        content_type = response.headers.get('Content-Type', b'').decode('utf-8')
        
        if 'text/html' in content_type:
            content = response.text
        else:
            content = response.body.decode('utf-8', errors='ignore')
        
        headers = dict(response.headers)
        
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO crawl_results (domain_id, url, status_code, content, headers)
                VALUES (?, ?, ?, ?, ?)
            ''', (domain_id, response.url, response.status, content, json.dumps(headers)))
            conn.commit()
        
        # Only follow links if we're still within depth limit and content is HTML
        if depth < self.max_depth - 1 and 'text/html' in content_type:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Limit the number of links we follow to prevent getting stuck
            links_followed = 0
            max_links = 3  # Only follow up to 3 links per page
            
            for link in soup.find_all('a', href=True):
                if links_followed >= max_links:
                    break
                    
                href = link['href']
                absolute_url = urljoin(response.url, href)
                
                if self.should_follow(absolute_url):
                    links_followed += 1
                    yield response.follow(absolute_url, callback=self.parse, meta={'domain_id': domain_id, 'depth': depth + 1},
                                       errback=self.errback_handler, dont_filter=True, timeout=self.timeout)
    
    def errback_handler(self, failure):
        # Handle timeouts and other errors
        self.logger.error(repr(failure))
        return None
    
    def should_follow(self, url):
        try:
            domain = self.extract_domain(url)
            return domain in self.allowed_domains and url not in self.visited_urls
        except:
            return False

class CrawlerManager:
    def __init__(self, db, config):
        self.db = db
        self.config = config
    
    def run_crawler(self, seeds):
        configure_logging()
        settings = get_project_settings()
        
        # Update settings with our config
        for key, value in self.config.items():
            settings.set(key.upper(), value)
        
        # Add timeout settings
        settings.set('DOWNLOAD_TIMEOUT', 10)  # Reduced timeout
        settings.set('CONCURRENT_REQUESTS_PER_DOMAIN', 1)  # Reduce concurrency to avoid timeouts
        settings.set('CONCURRENT_REQUESTS', 3)  # Reduce overall concurrency
        settings.set('DEPTH_LIMIT', 1)  # Limit crawl depth
        
        runner = CrawlerRunner(settings)
        d = runner.crawl(PhishingSpider, seeds=seeds, db=self.db)
        d.addBoth(lambda _: reactor.stop)
        
        # Set up timeout for the entire crawling process
        reactor.callLater(60, reactor.stop)  # Stop after 1 minute
        
        reactor.run()

def create_robust_session():
    """Create a robust requests session with retry strategy"""
    session = requests.Session()
    
    # Set retry strategy with correct parameter names for newer urllib3 versions
    retry_strategy = Retry(
        total=1,  # Only retry once to speed up the process
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    
    # Mount HTTP and HTTPS adapters with retry strategy
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set headers
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })
    
    # Disable SSL verification
    session.verify = False
    
    # Set timeout
    session.timeout = 8  # Reduced timeout
    
    return session

def clean_url(url):
    """Clean and normalize URL for crawling"""
    # Remove any leading/trailing whitespace
    url = url.strip()
    
    # If URL already has protocol, use as is
    if url.startswith(('http://', 'https://')):
        return url
    
    # Otherwise, assume it's a domain and add https://
    return f"https://{url}"

def is_valid_domain_format(domain):
    """Check if domain has a valid format"""
    # Basic domain name validation
    if not domain or len(domain) < 3:
        return False
    
    # Check for invalid characters
    if re.match(r'^[a-zA-Z0-9.-]+$', domain) is None:
        return False
    
    # Check if it starts or ends with invalid characters
    if domain.startswith('.') or domain.endswith('.') or domain.startswith('-') or domain.endswith('-'):
        return False
    
    # Check for consecutive dots
    if '..' in domain:
        return False
    
    # Check if it has at least one dot and valid TLD
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    # Check TLD length (should be at least 2 characters)
    if len(parts[-1]) < 2:
        return False
    
    return True

def can_resolve_domain(domain):
    """Check if a domain can be resolved (DNS lookup)"""
    try:
        # Try using socket.gethostbyname with a timeout
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False

def simple_crawl_domain(domain, db):
    """Simple crawler using requests for basic functionality with better SSL handling"""
    try:
        # Clean the domain/URL
        clean_domain = clean_url(domain)
        
        # Extract just the domain part for storage
        if "://" in clean_domain:
            parsed = urlparse(clean_domain)
            domain_name = parsed.netloc
        else:
            domain_name = clean_domain
        
        # Validate domain format
        if not is_valid_domain_format(domain_name):
            print(f"Skipping invalid domain format: {domain_name}")
            return None, None, None, None
        
        # Check if domain can be resolved
        if not can_resolve_domain(domain_name):
            print(f"Skipping unresolvable domain: {domain_name}")
            return None, None, None, None
        
        # Try to crawl with the cleaned URL
        urls_to_try = [
            clean_domain,
            clean_domain.replace('https://', 'http://'),
            f"https://www.{domain_name}",
            f"http://www.{domain_name}"
        ]
        
        # Create a robust session
        session = create_robust_session()
        
        for url in urls_to_try:
            try:
                # Set a timeout for the request (8 seconds)
                response = session.get(url, timeout=8)
                
                # Add domain to database and get domain_id
                domain_id = db.add_domain(domain_name, 'suspected')
                
                # Store the crawl result
                with sqlite3.connect(db.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO crawl_results (domain_id, url, status_code, content, headers)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (domain_id, url, response.status_code, response.text, json.dumps(dict(response.headers))))
                    conn.commit()
                
                print(f"Crawled {domain_name} at {url} (Status: {response.status_code})")
                
                # Return the content and other details
                return url, response.status_code, response.text, dict(response.headers)
                    
            except requests.exceptions.SSLError as e:
                print(f"SSL error for {url}: {e}")
                # Try with SSL verification disabled
                try:
                    response = session.get(url, verify=False, timeout=8)
                    
                    # Add domain to database and get domain_id
                    domain_id = db.add_domain(domain_name, 'suspected')
                    
                    # Store the crawl result
                    with sqlite3.connect(db.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO crawl_results (domain_id, url, status_code, content, headers)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (domain_id, url, response.status_code, response.text, json.dumps(dict(response.headers))))
                        conn.commit()
                    
                    print(f"Crawled {domain_name} at {url} with SSL verification disabled (Status: {response.status_code})")
                    
                    # Return the content and other details
                    return url, response.status_code, response.text, dict(response.headers)
                except Exception as e:
                    print(f"Failed to crawl {url} even with SSL verification disabled: {e}")
                    continue
            except requests.exceptions.Timeout as e:
                print(f"Timeout error for {url}: {e}")
                continue
            except requests.exceptions.ConnectionError as e:
                print(f"Connection error for {url}: {e}")
                continue
            except requests.RequestException as e:
                print(f"Request error for {url}: {e}")
                continue
        
        # If we get here, all URLs failed
        print(f"Could not crawl {domain_name} with any URL")
        return None, None, None, None
        
    except Exception as e:
        print(f"Error crawling {domain}: {e}")
        return None, None, None, None

def batch_crawl_domains(domains, db, max_workers=3):
    """Crawl multiple domains in parallel with a timeout"""
    results = {}
    
    # Use ThreadPoolExecutor for parallel crawling
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all crawl tasks
        future_to_domain = {
            executor.submit(simple_crawl_domain, domain, db): domain 
            for domain in domains
        }
        
        # Process results as they complete with a longer timeout
        try:
            for future in concurrent.futures.as_completed(future_to_domain, timeout=300):  # 5 minutes total timeout
                domain = future_to_domain[future]
                try:
                    url, status_code, content, headers = future.result()
                    results[domain] = (url, status_code, content, headers)
                except Exception as e:
                    print(f"Error crawling {domain}: {e}")
                    results[domain] = (None, None, None, None)
        except concurrent.futures.TimeoutError:
            print("Timeout reached while waiting for crawling to complete")
            # Cancel any remaining futures
            for future in future_to_domain:
                future.cancel()
            
            # Process any completed futures
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                if future.done():
                    try:
                        url, status_code, content, headers = future.result()
                        results[domain] = (url, status_code, content, headers)
                    except Exception as e:
                        print(f"Error crawling {domain}: {e}")
                        results[domain] = (None, None, None, None)
    
    return results