@echo off
echo Setting up Phishing Detection System...

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH. Please install Python 3.7+ and try again.
    pause
    exit /b 1
)

echo Using Python:
python --version

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install requirements
echo Installing requirements...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

REM Create necessary directories
echo Creating directories...
if not exist "data" mkdir data
if not exist "models" mkdir models
if not exist "reports" mkdir reports
if not exist "screenshots" mkdir screenshots
if not exist "logs" mkdir logs

REM Create sample CSE domains file
echo Creating sample CSE domains file...
echo bankofamerica.com > data\cse_domains.txt
echo chase.com >> data\cse_domains.txt
echo wellsargo.com >> data\cse_domains.txt
echo citibank.com >> data\cse_domains.txt
echo paypal.com >> data\cse_domains.txt
echo irs.gov >> data\cse_domains.txt
echo ssa.gov >> data\cse_domains.txt
echo microsoft.com >> data\cse_domains.txt
echo google.com >> data\cse_domains.txt
echo amazon.com >> data\cse_domains.txt

REM Create sample training data
echo Creating sample training data...
python -c "from detector import PhishingDetector; detector = PhishingDetector(); detector.create_sample_training_data('data/training_data.csv')"

echo Setup complete!
echo.
echo Next steps:
echo 1. Activate virtual environment: venv\Scripts\activate.bat
echo 2. Train the model: python main.py train
echo 3. Crawl domains: python main.py crawl
echo 4. Detect phishing: python main.py detect
echo 5. Start monitoring: python main.py monitor
pause