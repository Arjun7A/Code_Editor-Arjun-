from fastapi import APIRouter
from app.schemas.predict_schemas import PredictRiskRequest, PredictRiskResponse
from app.services.ml_predictor import MLPredictor
from app.core.config import settings

router = APIRouter()

# Initialize predictor with model path from config
predictor = MLPredictor(model_path=settings.ML_MODEL_PATH)


@router.post("/predict_risk", response_model=PredictRiskResponse)
async def predict_risk(request: PredictRiskRequest):
    """
    Predict risk score for a Pull Request using the trained XGBoost model.

    Accepts 12 PR features and returns a risk score (0-1),
    risk label (high/low), and feature importance breakdown.
    """
    features = request.model_dump()

    # Convert bool to int for model compatibility
    features["has_test_changes"] = int(features["has_test_changes"])

    result = predictor.predict_risk(features)

    return PredictRiskResponse(**result)
