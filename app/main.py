from fastapi import FastAPI
from pydantic import BaseModel

from app.analyzer import analyze_eml_content


app = FastAPI()


class EmailAnalysisRequest(BaseModel):
    raw_email: str


@app.get("/")
def root():
    return {"message": "Phishing Defense API is running."}

@app.post("/analyze-email")
def analyze_email(request: EmailAnalysisRequest):
    result = analyze_eml_content(request.raw_email)
    return result