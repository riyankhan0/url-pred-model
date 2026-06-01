from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import re
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from pathlib import Path

app = FastAPI(title="URL Threat Detection API", version="1.0.0")

# ── Model loading ──────────────────────────────────────────────
BASE_DIR = Path(__file__).parent

def load_models():
    models = {}
    for name, fname in [
        ("lgb",  "lgb_model.pkl"),
        ("xgb",  "xgboost_model.pkl"),
        ("gbdt", "gbdt_model.pkl"),
        ("rf",   "random_forest_model.pkl"),
    ]:
        with open(BASE_DIR / fname, "rb") as f:
            models[name] = pickle.load(f)
    return models

MODELS = load_models()

# ── Feature extraction ─────────────────────────────────────────
XSS_SQL_KEYWORDS = (
    "<script>", "<script", "alert(", "onmouseover", "onload", "onclick",
    "onerror", "eval(", "document.cookie", "window.location", "innerHTML",
    "fromCharCode(", "encodeURIComponent(", "setTimeout(", "setInterval(",
    "xhr.open(", "xhr.send(", "parent.frames[", "prompt(", "confirm(",
    "<img src=", "<audio src=", "<video src=", "<svg/onload=", "<iframe src=",
    "<body onload=", "<form action=", "<style>", "<xss>",
    "OR 1=1", "AND 1=1", "SELECT", "FROM", "WHERE", "INSERT", "UPDATE",
    "DELETE", "EXECUTE", "UNION", "JOIN", "DROP", "CREATE", "ALTER",
    "TRUNCATE", "HAVING", "ORDER BY", "GROUP BY",
)

def extract_features(url: str) -> dict:
    suspicious = 0

    # Normalize URL (extract path only if full URL)
    try:
        normalized = 'http://www.example.com/' + url.split('/', 3)[3]
    except Exception:
        normalized = url
        suspicious += 1

    # IOCs count
    iocs = sum(url.count(k) for k in XSS_SQL_KEYWORDS)
    suspicious += iocs

    parsed = urlparse(normalized)

    def no_of_dir(u):
        return urlparse(u).path.count('/')

    def no_of_embed(u):
        return urlparse(u).path.count('//')

    def digit_count(u):
        return sum(1 for c in u if c.isnumeric())

    def special_char_count(u):
        return sum(1 for c in u if not c.isalpha() and not c.isdigit())

    return {
        "period_count":           url.count('.'),
        "www_count":              url.count('www'),
        "at_count":               url.count('@'),
        "directory_count":        no_of_dir(normalized),
        "embedded_domain_count":  no_of_embed(normalized),
        "less_than_count":        url.count('<'),
        "open_brace_count":       url.count('{'),
        "close_brace_count":      url.count('}'),
        "plus_count":             url.count('+'),
        "minus_count":            url.count('-'),
        "double_quote_count":     url.count('"'),
        "colon_count":            url.count(':'),
        "semicolon_count":        url.count(';'),
        "asterisk_count":         url.count('*'),
        "backtick_count":         url.count('`'),
        "tilde_count":            url.count('~'),
        "ampersand_count":        url.count('&'),
        "exclamation_count":      url.count('!'),
        "digit_count":            digit_count(url),
        "special_char_count":     special_char_count(url),
        "percent_count":          url.count('%'),
        "question_mark_count":    url.count('?'),
        "equal_sign_count":       url.count('='),
        "url_length":             len(url),
        "iocs_count":             iocs,
        "_suspicious":            suspicious,   # internal, excluded from X
    }

FEATURE_COLS = [
    "period_count", "www_count", "at_count", "directory_count",
    "embedded_domain_count", "less_than_count", "open_brace_count",
    "close_brace_count", "plus_count", "minus_count", "double_quote_count",
    "colon_count", "semicolon_count", "asterisk_count", "backtick_count",
    "tilde_count", "ampersand_count", "exclamation_count", "digit_count",
    "special_char_count", "percent_count", "question_mark_count",
    "equal_sign_count", "url_length", "iocs_count",
]

# ── Request / Response schemas ─────────────────────────────────
class URLRequest(BaseModel):
    url: str

class BulkURLRequest(BaseModel):
    urls: list[str]

# ── Endpoints ──────────────────────────────────────────────────
@app.get("/")
def root():
    return {"message": "URL Threat Detection API is running. Use POST /predict or POST /predict/bulk"}


@app.post("/predict")
def predict_single(req: URLRequest):
    """Predict whether a single URL is Malicious or Benign."""
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    feats = extract_features(url)
    suspicious = feats.pop("_suspicious")
    X = pd.DataFrame([feats])[FEATURE_COLS]

    preds = {
        "lgb":  int(MODELS["lgb"].predict(X)[0]),
        "xgb":  int(MODELS["xgb"].predict(X)[0]),
        "gbdt": int(MODELS["gbdt"].predict(X)[0]),
        "rf":   int(MODELS["rf"].predict(X)[0]),
    }

    avg_confidence = np.mean(list(preds.values()))
    verdict = "Benign" if (avg_confidence < 0.6 and suspicious == 0) else "Malicious"

    return {
        "url":              url,
        "verdict":          verdict,
        "avg_confidence":   round(float(avg_confidence), 4),
        "suspicious_score": suspicious,
        "model_predictions": preds,
    }


@app.post("/predict/bulk")
def predict_bulk(req: BulkURLRequest):
    """Predict for a list of URLs at once."""
    if not req.urls:
        raise HTTPException(status_code=400, detail="URLs list cannot be empty")

    results = []
    for url in req.urls:
        url = url.strip()
        feats = extract_features(url)
        suspicious = feats.pop("_suspicious")
        X = pd.DataFrame([feats])[FEATURE_COLS]

        preds = {
            "lgb":  int(MODELS["lgb"].predict(X)[0]),
            "xgb":  int(MODELS["xgb"].predict(X)[0]),
            "gbdt": int(MODELS["gbdt"].predict(X)[0]),
            "rf":   int(MODELS["rf"].predict(X)[0]),
        }
        avg_confidence = np.mean(list(preds.values()))
        verdict = "Benign" if (avg_confidence < 0.6 and suspicious == 0) else "Malicious"

        results.append({
            "url":               url,
            "verdict":           verdict,
            "avg_confidence":    round(float(avg_confidence), 4),
            "suspicious_score":  suspicious,
            "model_predictions": preds,
        })

    return {"results": results, "total": len(results)}
