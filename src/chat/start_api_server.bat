:: Terminal 1: For the chatbot api

@echo off
echo Installing dependencies...
pip install -r ..\requirements.txt

echo Starting FastAPI server...
uvicorn chatbot:app --reload --port 8000

