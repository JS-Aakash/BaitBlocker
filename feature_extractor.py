import re
import whois
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import entropy
import json
import math
import requests
from bs4 import BeautifulSoup
import tldextract

class FeatureExtractor:
    def __init__(self):
        self.url_features = [
            'url_length', 'num_dots', 'repeated_digits', 'special_chars',
            'num_hyphens', 'num_slashes', 'num_underscores', 'num_question_marks',
            'num_equal_signs', 'num_dollar_signs', 'num_exclamation', 'num_hashtags',
            'num_percent_signs', 'domain_length', 'domain_hyphens', 'domain_special_chars'
        ]
        
        self.subdomain_features = [
            'num_subdomains', 'avg_subdomain_length', 'subdomain_complexity',
            'subdomain_hyphen', 'subdomain_repeated_digits'
        ]
        
        self.path_features = [
            'path_length', 'has_query', 'has_fragment', 'has_anchor'
        ]
    
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
    
    def extract_url_features(self, url):
        parsed = urlparse(url)
        features = {}
        
        # URL-based features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['repeated_digits'] = len(re.findall(r'(\d)\1{1,}', url))
        features['special_chars'] = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url))
        features['num_hyphens'] = url.count('-')
        features['num_slashes'] = url.count('/')
        features['num_underscores'] = url.count('_')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_dollar_signs'] = url.count('$')
        features['num_exclamation'] = url.count('!')
        features['num_hashtags'] = url.count('#')
        features['num_percent_signs'] = url.count('%')
        
        # Domain features
        domain = parsed.netloc
        features['domain_length'] = len(domain)
        features['domain_hyphens'] = domain.count('-')
        features['domain_special_chars'] = len(re.findall(r'[^a-zA-Z0-9.-]', domain))
        
        # Subdomain features
        subdomains = domain.split('.')
        features['num_subdomains'] = len(subdomains) - 2  # Subtract TLD and main domain
        if features['num_subdomains'] > 0:
            features['avg_subdomain_length'] = sum(len(s) for s in subdomains[:-2]) / features['num_subdomains']
            features['subdomain_complexity'] = self.calculate_entropy(''.join(subdomains[:-2]))
            features['subdomain_hyphen'] = any('-' in s for s in subdomains[:-2])
            features['subdomain_repeated_digits'] = any(re.search(r'(\d)\1{1,}', s) for s in subdomains[:-2])
        else:
            features.update({
                'avg_subdomain_length': 0,
                'subdomain_complexity': 0,
                'subdomain_hyphen': False,
                'subdomain_repeated_digits': False
            })
        
        # Path features
        path = parsed.path
        features['path_length'] = len(path)
        features['has_query'] = bool(parsed.query)
        features['has_fragment'] = bool(parsed.fragment)
        features['has_anchor'] = '#' in url
        
        # Additional URL features
        features['ip_in_url'] = 1 if self.is_ip_address(domain) else 0
        features['at_in_url'] = 1 if '@' in url else 0
        features['punycode_in_url'] = 1 if 'xn--' in domain else 0
        
        # Calculate typosquatting score
        features['typosquatting_score'] = 0
        cse_brands = ['google', 'microsoft', 'amazon', 'facebook', 'instagram', 'twitter', 'linkedin', 'youtube', 'paypal', 'bankofamerica', 'chase', 'citibank', 'wellsfargo', 'adobe', 'apple']
        for brand in cse_brands:
            if self.is_typosquatting(domain, brand):
                features['typosquatting_score'] = 0.8
                break
        
        # Calculate entropy
        features['domain_entropy'] = self.calculate_entropy(domain)
        features['path_entropy'] = self.calculate_entropy(path)
        
        return features
    
    def extract_domain_features(self, domain):
        features = {}
        
        # Domain registration info
        try:
            domain_info = whois.whois(domain)
            features['domain_age_days'] = self.calculate_domain_age(domain_info.creation_date)
            features['registrar'] = str(domain_info.registrar) if domain_info.registrar else 'Unknown'
            features['registrant'] = str(domain_info.registrant) if domain_info.registrant else 'Unknown'
            features['country'] = str(domain_info.country) if domain_info.country else 'Unknown'
            features['name_servers'] = len(domain_info.name_servers) if domain_info.name_servers else 0
        except Exception as e:
            features.update({
                'domain_age_days': -1,
                'registrar': 'Unknown',
                'registrant': 'Unknown',
                'country': 'Unknown',
                'name_servers': 0
            })
        
        # IP and hosting info
        try:
            ip = socket.gethostbyname(domain)
            features['ip'] = ip
            features['hosting_country'] = self.get_ip_country(ip)
        except:
            features.update({'ip': 'Unknown', 'hosting_country': 'Unknown'})
        
        # SSL Certificate info
        features['ssl_valid'] = self.check_ssl_certificate(domain)
        
        # Additional certificate features
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    if 'notAfter' in cert:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        validity_days = (not_after - datetime.now()).days
                        features['cert_validity_days'] = validity_days
                        
                        # Check if certificate is valid for less than 30 days
                        if validity_days < 30:
                            features['short_cert_validity'] = 1
                        else:
                            features['short_cert_validity'] = 0
                    else:
                        features['cert_validity_days'] = 0
                        features['short_cert_validity'] = 0
                    
                    # Check CN/SAN mismatch
                    subject = cert.get('subject', {})
                    if isinstance(subject, list) and subject:
                        subject = subject[0]
                    
                    cn = subject.get('commonName', '')
                    san = cert.get('subjectAltName', [])
                    
                    if cn and cn != domain:
                        features['cert_cn_mismatch'] = 1
                    elif san and domain not in san:
                        features['cert_cn_mismatch'] = 1
                    else:
                        features['cert_cn_mismatch'] = 0
        except:
            features.update({
                'cert_validity_days': 0,
                'short_cert_validity': 0,
                'cert_cn_mismatch': 0
            })
        
        return features
    
    def extract_content_features(self, html_content):
        features = {}
        
        # Basic content features
        features['content_length'] = len(html_content)
        features['num_links'] = len(re.findall(r'<a\s+href=', html_content.lower()))
        features['num_forms'] = len(re.findall(r'<form', html_content.lower()))
        features['num_scripts'] = len(re.findall(r'<script', html_content.lower()))
        features['num_iframes'] = len(re.findall(r'<iframe', html_content.lower()))
        
        # Favicon analysis
        features['favicon_present'] = '<link rel="icon"' in html_content.lower()
        
        # Login-related keywords
        login_keywords = ['login', 'signin', 'password', 'username', 'credential', 'auth']
        features['login_keywords_count'] = sum(1 for keyword in login_keywords if keyword in html_content.lower())
        
        # Brand keywords
        brand_keywords = ['paypal', 'bank', 'amazon', 'google', 'microsoft', 'apple', 'facebook']
        features['brand_keywords_count'] = sum(1 for keyword in brand_keywords if keyword in html_content.lower())
        
        # Form features
        features['has_password_field'] = 'type="password"' in html_content.lower()
        features['has_hidden_fields'] = 'type="hidden"' in html_content.lower()
        
        # External scripts
        features['has_external_scripts'] = 'src="http' in html_content.lower()
        
        # Error page analysis
        features['is_error_page'] = self.is_error_page(html_content)
        
        if features['is_error_page']:
            # Check for brand impersonation in error page
            features['error_page_brand_impersonation'] = self.check_error_page_brand_impersonation(html_content)
            # Check for urgent language in error page
            features['error_page_urgent_language'] = self.check_error_page_urgent_language(html_content)
        else:
            features['error_page_brand_impersonation'] = 0
            features['error_page_urgent_language'] = 0
        
        # Established domain features
        features['is_established_domain'] = self.is_established_domain(html_content)
        features['has_privacy_policy'] = 'privacy' in html_content.lower()
        features['has_contact_info'] = 'contact' in html_content.lower()
        features['has_terms_of_service'] = 'terms' in html_content.lower() or 'tos' in html_content.lower()
        
        # Domain reputation score (simplified)
        features['domain_reputation_score'] = self.calculate_domain_reputation(html_content)
        
        # Additional content features
        features['has_meta_refresh'] = 'meta http-equiv="refresh"' in html_content.lower()
        features['form_action_external'] = 0
        features['has_obfuscated_js'] = 0
        
        # Check for form action to external domain
        if 'action=' in html_content.lower():
            soup = BeautifulSoup(html_content, 'html.parser')
            for form in soup.find_all('form', action=True):
                action = form.get('action', '')
                if action and urlparse(action).netloc != urlparse(html_content).netloc:
                    features['form_action_external'] = 1
                    break
        
        # Check for obfuscated JavaScript
        if 'eval(' in html_content or 'btoa(' in html_content or 'atob(' in html_content or 'String.fromCharCode(' in html_content:
            features['has_obfuscated_js'] = 1
        
        # Check for mixed content (HTTPS page with HTTP resources)
        features['has_mixed_content'] = 0
        if 'https://' in html_content and 'http://' in html_content:
            # Check if there are HTTP resources in an HTTPS page
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Check for HTTP scripts
            for script in soup.find_all('script', src=True):
                src = script.get('src', '')
                if src.startswith('http://'):
                    features['has_mixed_content'] = 1
                    break
            
            # Check for HTTP iframes
            if features['has_mixed_content'] == 0:
                for iframe in soup.find_all('iframe', src=True):
                    src = iframe.get('src', '')
                    if src.startswith('http://'):
                        features['has_mixed_content'] = 1
                        break
            
            # Check for HTTP images
            if features['has_mixed_content'] == 0:
                for img in soup.find_all('img', src=True):
                    src = img.get('src', '')
                    if src.startswith('http://'):
                        features['has_mixed_content'] = 1
                        break
        
        return features
    
    def extract_all_features(self, url, html_content):
        """Extract all features from URL and content"""
        features = {}
        
        # URL features
        url_features = self.extract_url_features(url)
        features.update(url_features)
        
        # Domain features
        parsed = urlparse(url)
        domain = parsed.netloc
        domain_features = self.extract_domain_features(domain)
        features.update(domain_features)
        
        # Content features
        content_features = self.extract_content_features(html_content)
        features.update(content_features)
        
        # Add domain to features for reference
        features['domain'] = domain
        features['url'] = url
        features['content'] = html_content
        
        return features
    
    def calculate_domain_age(self, creation_date):
        """Calculate domain age in days"""
        if not creation_date:
            return -1
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if isinstance(creation_date, str):
            try:
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            except:
                return -1
        
        if isinstance(creation_date, datetime):
            return (datetime.now() - creation_date).days
        
        return -1
    
    def get_ip_country(self, ip):
        """Get country from IP (simplified version)"""
        try:
            # This is a simplified version - in production, use a proper GeoIP database
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            return data.get('country', 'Unknown')
        except:
            return 'Unknown'
    
    def check_ssl_certificate(self, domain):
        """Check if SSL certificate is valid"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return True
        except:
            return False
    
    def is_error_page(self, content):
        """Check if the content appears to be an error page"""
        error_indicators = [
            'error', 'not found', '404', '403', '500', 'service unavailable',
            'page not found', 'cannot be found', 'does not exist'
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in error_indicators)
    
    def check_error_page_brand_impersonation(self, content):
        """Check if an error page impersonates a brand"""
        brands = ['google', 'microsoft', 'amazon', 'facebook', 'instagram', 'twitter', 'linkedin', 'youtube', 'paypal', 'bankofamerica', 'chase', 'citibank', 'wellsfargo', 'adobe', 'apple']
        
        content_lower = content.lower()
        brand_count = sum(1 for brand in brands if brand in content_lower)
        
        # If multiple brands are mentioned on an error page, it's suspicious
        return min(brand_count, 5)  # Cap at 5
    
    def check_error_page_urgent_language(self, content):
        """Check for urgent language in error page"""
        urgent_phrases = [
            'urgent', 'immediately', 'act now', 'verify now', 'confirm now',
            'limited time', 'expire soon', 'suspend', 'blocked', 'warning',
            'security alert', 'account suspended', 'verify your account'
        ]
        
        content_lower = content.lower()
        urgent_count = sum(1 for phrase in urgent_phrases if phrase in content_lower)
        
        return min(urgent_count, 5)  # Cap at 5
    
    def is_established_domain(self, content):
        """Check if the content indicates an established domain"""
        established_indicators = [
            'about us', 'company', 'careers', 'investor relations',
            'press release', 'news', 'blog', 'contact us', 'support',
            'privacy policy', 'terms of service', 'legal', 'copyright'
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in established_indicators)
    
    def calculate_domain_reputation(self, content):
        """Calculate a simplified domain reputation score based on content"""
        score = 5  # Start with neutral score
        
        # Positive indicators
        positive_indicators = [
            ('about us', 1), ('company', 1), ('careers', 1),
            ('investor relations', 1), ('press release', 1), ('news', 1),
            ('blog', 1), ('contact us', 1), ('support', 1),
            ('privacy policy', 1), ('terms of service', 1), ('legal', 1),
            ('copyright', 1), ('established', 1)
        ]
        
        # Negative indicators
        negative_indicators = [
            ('verify now', -1), ('act now', -1), ('urgent', -1),
            ('limited time', -1), ('expire soon', -1), ('suspend', -1),
            ('blocked', -1), ('security alert', -1), ('account suspended', -1),
            ('verify your account', -1), ('confirm your account', -1)
        ]
        
        content_lower = content.lower()
        
        for indicator, value in positive_indicators:
            if indicator in content_lower:
                score += value
        
        for indicator, value in negative_indicators:
            if indicator in content_lower:
                score += value
        
        # Ensure score is within 0-10 range
        return max(0, min(score, 10))
    
    def is_typosquatting(self, domain, brand):
        """Check if a domain is a typosquatting of a brand"""
        domain_lower = domain.lower()
        brand_lower = brand.lower()
        
        # Character substitution
        char_substitutions = {
            'a': ['4', '@', 'α', 'а'],
            'b': ['8', 'ß'],
            'e': ['3', '€', 'е'],
            'g': ['9', 'q'],
            'i': ['1', '!', '|', 'і'],
            'l': ['1', '|', 'і'],
            'o': ['0', 'ο', 'о'],
            's': ['5', '$', 'ѕ'],
            't': ['7', '+', 'т'],
            'z': ['2', 'ʒ'],
        }
        
        # Check for character substitutions
        for char, subs in char_substitutions.items():
            if char in brand_lower:
                for sub in subs:
                    if sub in domain_lower:
                        return True
        
        # Check for character omission
        if len(brand_lower) > 1 and domain_lower.startswith(brand_lower[1:]):
            return True
        if len(brand_lower) > 1 and domain_lower.startswith(brand_lower[:-1]):
            return True
        
        # Check for character duplication
        if len(brand_lower) > 0 and domain_lower.startswith(brand_lower[0] + brand_lower[0] + brand_lower):
            return True
        if len(brand_lower) > 0 and domain_lower.startswith(brand_lower + brand_lower[-1]):
            return True
        
        return False