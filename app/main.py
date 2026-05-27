from fastapi import FastAPI

from app.analyzer import analyze_eml_content
from app.models import EmailInput, PhishingAnalysisResult


app = FastAPI()


@app.get("/")
def root():
    return {"message": "Phishing Defense API is running."}

@app.post("/analyze-email", response_model=PhishingAnalysisResult)
def analyze_email(request: EmailInput):
    result = analyze_eml_content(request.raw_email)
    return result