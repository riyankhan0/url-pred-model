from flask import Flask, request, jsonify
import re
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from pathlib import Path

app = Flask(__name__)

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
    print("[OK] All models loaded")
    return models

MODELS = load_models()

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

FEATURE_COLS = [
    "period_count", "www_count", "at_count", "directory_count",
    "embedded_domain_count", "less_than_count", "open_brace_count",
    "close_brace_count", "plus_count", "minus_count", "double_quote_count",
    "colon_count", "semicolon_count", "asterisk_count", "backtick_count",
    "tilde_count", "ampersand_count", "exclamation_count", "digit_count",
    "special_char_count", "percent_count", "question_mark_count",
    "equal_sign_count", "url_length", "iocs_count",
]

def extract_features(url):
    suspicious = 0
    try:
        normalized = "http://www.example.com/" + url.split("/", 3)[3]
    except Exception:
        normalized = url
        suspicious += 1
    iocs = sum(url.count(k) for k in XSS_SQL_KEYWORDS)
    suspicious += iocs
    feats = {
        "period_count":          url.count("."),
        "www_count":             url.count("www"),
        "at_count":              url.count("@"),
        "directory_count":       urlparse(normalized).path.count("/"),
        "embedded_domain_count": urlparse(normalized).path.count("//"),
        "less_than_count":       url.count("<"),
        "open_brace_count":      url.count("{"),
        "close_brace_count":     url.count("}"),
        "plus_count":            url.count("+"),
        "minus_count":           url.count("-"),
        "double_quote_count":    url.count('"'),
        "colon_count":           url.count(":"),
        "semicolon_count":       url.count(";"),
        "asterisk_count":        url.count("*"),
        "backtick_count":        url.count("`"),
        "tilde_count":           url.count("~"),
        "ampersand_count":       url.count("&"),
        "exclamation_count":     url.count("!"),
        "digit_count":           sum(1 for c in url if c.isnumeric()),
        "special_char_count":    sum(1 for c in url if not c.isalpha() and not c.isdigit()),
        "percent_count":         url.count("%"),
        "question_mark_count":   url.count("?"),
        "equal_sign_count":      url.count("="),
        "url_length":            len(url),
        "iocs_count":            iocs,
    }
    return feats, suspicious

@app.route("/")
def home():
    return jsonify({"status": "running", "endpoints": ["/predict", "/predict/bulk"]})

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Send JSON with url key"}), 400
    url = data["url"].strip()
    feats, suspicious = extract_features(url)
    X = pd.DataFrame([feats])[FEATURE_COLS]
    preds = {
        "lgb":  int(MODELS["lgb"].predict(X)[0]),
        "xgb":  int(MODELS["xgb"].predict(X)[0]),
        "gbdt": int(MODELS["gbdt"].predict(X)[0]),
        "rf":   int(MODELS["rf"].predict(X)[0]),
    }
    avg_confidence = float(np.mean(list(preds.values())))
    verdict = "Benign" if (avg_confidence < 0.6 and suspicious == 0) else "Malicious"
    return jsonify({"url": url, "verdict": verdict, "avg_confidence": round(avg_confidence, 4), "suspicious_score": suspicious, "model_predictions": preds})

@app.route("/predict/bulk", methods=["POST"])
def predict_bulk():
    data = request.get_json()
    if not data or "urls" not in data:
        return jsonify({"error": "Send JSON with urls key"}), 400
    results = []
    for url in data["urls"]:
        url = url.strip()
        feats, suspicious = extract_features(url)
        X = pd.DataFrame([feats])[FEATURE_COLS]
        preds = {
            "lgb":  int(MODELS["lgb"].predict(X)[0]),
            "xgb":  int(MODELS["xgb"].predict(X)[0]),
            "gbdt": int(MODELS["gbdt"].predict(X)[0]),
            "rf":   int(MODELS["rf"].predict(X)[0]),
        }
        avg_confidence = float(np.mean(list(preds.values())))
        verdict = "Benign" if (avg_confidence < 0.6 and suspicious == 0) else "Malicious"
        results.append({"url": url, "verdict": verdict, "avg_confidence": round(avg_confidence, 4), "suspicious_score": suspicious, "model_predictions": preds})
    return jsonify({"results": results, "total": len(results)})




import os
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port)