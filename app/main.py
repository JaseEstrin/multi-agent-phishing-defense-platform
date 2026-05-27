from fastapi import FastAPI

from app.analyzer import analyze_eml_file

app = FastAPI()


@app.get("/")
def root():
    return {"message": "Phishing Defense API is running."}

@app.post("/analyze-email")
def analyze_email(file_path: str):
    result = analyze_eml_file(file_path)
    return result