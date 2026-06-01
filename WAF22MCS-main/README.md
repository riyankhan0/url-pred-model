# URL Threat Detection — FastAPI

## Setup

```bash
pip install fastapi uvicorn pandas numpy scikit-learn xgboost lightgbm
```

## Run Server

Make sure all `.pkl` files are in the same folder as `main.py`, then:

```bash
uvicorn main:app --reload --port 8000
```

---

## Test via Terminal (curl)

### 1. Health check
```bash
curl http://127.0.0.1:8000/
```

### 2. Single URL — Malicious example
```bash
curl -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://careers.nadra.gov.pk/JobListing/JobApplication?VacancyId=<script>alert(\"xss\")</script>"}'
```

### 3. Single URL — Benign example
```bash
curl -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com/search?q=python+fastapi"}'
```

### 4. Bulk URLs
```bash
curl -X POST http://127.0.0.1:8000/predict/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://www.google.com",
      "https://example.com/page?id=1 OR 1=1--",
      "https://safe-site.org/about"
    ]
  }'
```

---

## Sample Response (single predict)

```json
{
  "url": "https://example.com/page?id=1 OR 1=1",
  "verdict": "Malicious",
  "avg_confidence": 0.75,
  "suspicious_score": 3,
  "model_predictions": {
    "lgb": 1,
    "xgb": 1,
    "gbdt": 1,
    "rf": 0
  }
}
```
