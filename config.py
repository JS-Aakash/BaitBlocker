import os

# Database Configuration
DATABASE_PATH = "data/phishing_detector.db"

# Crawler Configuration
CRAWLER_CONFIG = {
    'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'DOWNLOAD_DELAY': 2,
    'CONCURRENT_REQUESTS': 16,
    'CONCURRENT_REQUESTS_PER_DOMAIN': 4,
    'DEPTH_LIMIT': 3,
    'TIMEOUT': 30,
    'RETRY_TIMES': 3,
}

# Monitoring Configuration
MONITOR_CONFIG = {
    'check_interval': 86400,  # 24 hours in seconds
    'max_suspected_duration': 90,  # days
    'alert_threshold': 0.8,  # confidence threshold
}

# Output Configuration
OUTPUT_CONFIG = {
    'reports_dir': 'reports',
    'screenshots_dir': 'screenshots',
    'logs_dir': 'logs',
}

# Create directories if they don't exist
for dir_path in OUTPUT_CONFIG.values():
    os.makedirs(dir_path, exist_ok=True)