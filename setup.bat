@echo off
setlocal

py -3 -m venv venv
if errorlevel 1 exit /b 1

call venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo CISBenchChecker is ready.
echo Run: venv\Scripts\python cisbench.py --help
