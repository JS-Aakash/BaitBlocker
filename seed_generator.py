import tldextract
import random
import string
from itertools import product

class SeedGenerator:
    def __init__(self, cse_domains_file):
        self.cse_domains = self.load_cse_domains(cse_domains_file)
        self.char_variations = {
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
    
    def load_cse_domains(self, filename):
        try:
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Warning: {filename} not found. Using default CSE domains.")
            return [
                'bankofamerica.com',
                'chase.com',
                'wellsfargo.com',
                'citibank.com',
                'paypal.com',
                'irs.gov',
                'ssa.gov',
                'microsoft.com',
                'google.com',
                'amazon.com'
            ]
    
    def generate_typosquatting(self, domain):
        ext = tldextract.extract(domain)
        base_domain = ext.domain
        suffix = f"{ext.suffix}.{ext.subdomain}" if ext.subdomain else ext.suffix
        
        variations = []
        
        # Character substitution
        for char, subs in self.char_variations.items():
            if char in base_domain.lower():
                for sub in subs:
                    variations.append(base_domain.replace(char, sub) + '.' + suffix)
        
        # Missing/double characters
        if len(base_domain) > 1:
            variations.append(base_domain[:-1] + '.' + suffix)  # Missing last char
            variations.append(base_domain + base_domain[-1] + '.' + suffix)  # Double last char
        
        # Character transposition
        for i in range(len(base_domain) - 1):
            transposed = base_domain[:i] + base_domain[i+1] + base_domain[i] + base_domain[i+2:]
            variations.append(transposed + '.' + suffix)
        
        # Subdomain manipulation
        common_subdomains = ['www', 'login', 'secure', 'account', 'signin', 'auth']
        if not ext.subdomain:
            for sub in common_subdomains:
                variations.append(f"{sub}.{domain}")
        
        # TLD variations
        common_tlds = ['com', 'net', 'org', 'co', 'io', 'biz', 'info']
        if ext.suffix in common_tlds:
            for tld in common_tlds:
                if tld != ext.suffix:
                    variations.append(f"{base_domain}.{tld}")
        
        # Add random character variations
        for _ in range(5):
            pos = random.randint(0, len(base_domain) - 1)
            char = random.choice(string.ascii_lowercase + string.digits)
            mutated = base_domain[:pos] + char + base_domain[pos:]
            variations.append(mutated + '.' + suffix)
        
        return list(set(variations))  # Remove duplicates
    
    def generate_seeds(self, max_variations=50):
        seeds = []
        
        # DO NOT add original CSE domains - only generate variations
        for domain in self.cse_domains:
            variations = self.generate_typosquatting(domain)
            # Limit variations to avoid too many seeds
            seeds.extend(variations[:max_variations])
        
        return list(set(seeds))  # Remove duplicates