# 🛡️ PhishGuard AI — URL Phishing Detection System

A full-stack machine-learning cybersecurity project that estimates whether a URL is phishing or legitimate using **character-level TF-IDF**, **engineered lexical URL features**, and a **Random Forest classifier**.

> ⚠️ This project is intended for education, portfolio use and defensive security research. A model prediction should not be treated as a definitive security verdict.

## Features

- URL phishing/legitimate classification
- Phishing probability + risk score
- Explainable suspicious indicators
- 25+ lexical URL features
- Character-level TF-IDF (3–5 grams)
- Random Forest classifier
- FastAPI backend with Swagger docs
- React + Vite responsive frontend
- Unit/API tests
- Docker Compose
- GitHub Actions CI

## Architecture

```text
Browser
   |
   v
React / Vite Frontend
   |
POST /predict
   |
   v
FastAPI Backend
   |
   +--> URL lexical feature extractor
   |
   +--> Character TF-IDF
   |
   v
Scikit-learn ML Pipeline
   |
   v
Prediction + probability + indicators
```

## Repository structure

```text
url-phishing-detection/
├── backend/
│   ├── app/
│   │   ├── features.py
│   │   ├── main.py
│   │   └── model_service.py
│   ├── data/
│   │   └── urls.csv
│   ├── ml/
│   │   └── train.py
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── main.jsx
│   │   └── style.css
│   ├── .env.example
│   └── package.json
├── .github/workflows/ci.yml
├── docker-compose.yml
├── LICENSE
└── README.md
```

## 1. Run the backend

```bash
cd backend

python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
python ml/train.py
uvicorn app.main:app --reload
```

Backend:
- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`

## 2. Run the frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend:
- `http://localhost:5173`

## 3. Run tests

```bash
cd backend
pytest -q
```

## 4. Docker

```bash
docker compose up --build
```

## Dataset format

Replace `backend/data/urls.csv` with a larger research dataset before reporting meaningful accuracy.

Required format:

```csv
url,label
https://github.com,0
http://example-phishing-site.test/login,1
```

- `0` = legitimate
- `1` = phishing

The repository includes only a **small demonstration dataset** so the application works immediately. It is not suitable for claiming production-level model accuracy.

For a serious portfolio version, use a larger, balanced dataset assembled from reputable phishing feeds / academic datasets and legitimate-domain sources. Keep a data-source section in your README and respect each source's license and usage conditions.

## Features extracted

Examples include:

- URL length
- hostname/path/query length
- number of dots, slashes, hyphens and special characters
- digit ratio
- raw IP hostname
- HTTPS presence
- punycode
- URL shortener usage
- number of subdomains
- suspicious keywords
- URL entropy

## API example

Request:

```json
POST /predict
{
  "url": "http://192.168.10.10/login/verify-account"
}
```

Response:

```json
{
  "url": "http://192.168.10.10/login/verify-account",
  "label": "phishing",
  "phishing_probability": 0.91,
  "risk_score": 91.0,
  "indicators": [
    "Hostname uses a raw IP address",
    "Contains phishing-related keywords"
  ]
}
```

## ML methodology

1. Normalize and parse URLs.
2. Extract handcrafted lexical features.
3. Convert the raw URL into character n-gram TF-IDF features.
4. Combine both feature groups in a scikit-learn `ColumnTransformer`.
5. Train a class-weighted Random Forest.
6. Evaluate on a held-out test set.
7. Persist the complete preprocessing + model pipeline with `joblib`.

## Recommended next improvements

- Use 50k–500k+ properly sourced URLs
- Deduplicate URLs before train/test split
- Avoid temporal/data-source leakage
- Compare Logistic Regression, LightGBM/XGBoost and Random Forest
- Add ROC/PR curves and confusion-matrix visualizations
- Tune the classification threshold for phishing recall
- Add domain age / DNS / certificate features carefully
- Integrate a reputation service as a second signal
- Add scan history with PostgreSQL
- Add authentication and rate limiting
- Deploy frontend and backend separately
- Add ML experiment tracking

## Security note

The backend performs **lexical analysis only** and does not visit submitted URLs. This is intentional: automatically fetching arbitrary URLs can introduce SSRF and other security risks.

## Author

**Mohamed Yassine Chafra**  
Cybersecurity Engineering Student

If this project helped you, consider starring the repository.
