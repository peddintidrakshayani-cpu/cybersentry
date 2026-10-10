@echo off
REM CyberSentry API — start here, then open http://127.0.0.1:8000/docs
cd /d "%~dp0"
python -m pip install -q -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
