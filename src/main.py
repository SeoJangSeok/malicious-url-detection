from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from predictor import predict_url

app = FastAPI(title="Malicious URL Detection API", version="1.0.0.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: HttpUrl


class PredictionResponse(BaseModel):
    url: str
    rf_probability: float
    rf_prediction: int
    iso_anomaly_score: float
    iso_prediction: int
    risk_level: str


@app.get("/")
def read_root():
    return {"message": "Hello"}


@app.post("/predict", response_model=PredictionResponse)
def predict(request: URLRequest):
    try:
        result = predict_url(str(request.url))
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")
