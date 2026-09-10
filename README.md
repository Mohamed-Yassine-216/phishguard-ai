# 🛡️ PhishGuard AI

### Machine Learning-Based Phishing URL Detection & Risk Analysis

PhishGuard AI is a full-stack cybersecurity application that analyzes URLs and predicts whether they are **legitimate or potentially phishing**.

The system combines **character-level TF-IDF analysis** with **24 engineered URL security features** and a machine-learning classifier. It also provides an explainable risk assessment to help users understand why a URL may be suspicious.

---

## 🚀 Demo

PhishGuard AI provides a web dashboard where users can:

- Enter a URL for analysis
- Receive a phishing prediction
- View the phishing probability
- See a risk score and risk level
- Review detected security indicators
- Inspect extracted URL security features

---

## 🖥️ Application

### URL Analysis

The application accepts a URL and sends it to the FastAPI backend for analysis.

### Risk Assessment

The system returns:

- **LEGITIMATE** or **PHISHING**
- Phishing probability
- Risk score
- Risk level
- Security indicators
- Extracted URL features

---

## 🧠 Machine Learning Pipeline

The detection system combines two types of information:

### 1. Character-Level TF-IDF

Character n-grams are extracted from the complete URL using:

```text
Analyzer: character
N-gram range: 3–5
Maximum features: 30,000
Sublinear TF: enabled
```

Character-level TF-IDF helps the model learn suspicious URL patterns without relying only on predefined rules.

### 2. Engineered URL Security Features

The model uses 24 numerical URL features, including:

- URL length
- IP address detection
- Dot count
- HTTPS usage
- URL entropy
- Token count
- Subdomain count
- Query parameter count
- TLD length
- Path length
- Hyphens in domain
- Number of digits
- Suspicious file extensions
- Domain length
- Numeric character percentage
- Domain entropy
- Path segment count
- Non-standard port detection
- Encoded character detection
- `@` symbol detection
- Double slash detection
- Suspicious keyword count
- Suspicious keyword presence
- URL shortener detection

### 3. Classification

The TF-IDF representation and numerical security features are combined and passed to a **Logistic Regression classifier**.

The classifier produces a phishing probability that is converted into a risk score:

```text
0–49%   → LOW
50–79%  → MEDIUM
80–100% → HIGH
```

---

## 🏗️ Architecture

```text
                    ┌─────────────────────┐
                    │    React Frontend   │
                    │    PhishGuard AI    │
                    └──────────┬──────────┘
                               │
                               │ HTTP / JSON
                               ▼
                    ┌─────────────────────┐
                    │     FastAPI API     │
                    │      /predict       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   URL Feature       │
                    │     Extraction      │
                    │    24 Features      │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Character TF-IDF    │
                    │   30,000 features   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Numerical Security  │
                    │      Features       │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Logistic Regression │
                    │      Classifier      │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Risk Score &        │
                    │ Security Indicators │
                    └─────────────────────┘
```

---

## 📊 Model Evaluation

The model was evaluated using a **domain-aware unseen-hostname split**.

The dataset contains:

- **100,872 URLs**
- **64,002 unique hostnames**
- **79,756 training URLs**
- **21,116 testing URLs**
- **51,202 training hostnames**
- **12,800 testing hostnames**
- **0 hostname overlap**

### Results

| Metric | Score |
|---|---:|
| Accuracy | **99.93%** |
| Precision | **99.99%** |
| Recall | **99.90%** |
| F1 Score | **99.95%** |
| ROC-AUC | **100.00%** |

### Confusion Matrix

```text
                  Predicted
                Legit    Phishing

Actual Legit     7532       1
Actual Phishing    13    13570
```

The model produced:

- **13 false negatives**
- **1 false positive**

> These results represent evaluation on the available dataset and should not be interpreted as guaranteed real-world phishing detection performance.

---

## 📚 Dataset

The project was developed using the **LegitPhish** URL dataset.

The local training data was cleaned before model development by:

- Removing missing labels
- Removing duplicate URLs
- Normalizing the dataset labels
- Extracting URL security features

The dataset is **not included in this repository**.

This keeps the GitHub repository lightweight and separates the application source code from the research dataset.

To train the model yourself, place the appropriate dataset files under:

```text
backend/data/
```

Then run:

```powershell
python backend/ml/train.py
```

---

## 🛠️ Technology Stack

### Backend

- Python
- FastAPI
- Pydantic
- pandas
- scikit-learn
- SciPy
- joblib

### Machine Learning

- Logistic Regression
- Character-level TF-IDF
- Feature engineering
- Stratified evaluation
- Unseen-hostname evaluation

### Frontend

- React
- Vite
- JavaScript
- CSS

### DevOps

- Docker
- Docker Compose
- GitHub Actions
- Git

---

## 📁 Project Structure

```text
phishguard-ai/
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── backend/
│   ├── app/
│   │   ├── features.py
│   │   ├── main.py
│   │   └── model_service.py
│   │
│   ├── ml/
│   │   ├── train.py
│   │   ├── evaluate_domain_split.py
│   │   ├── phishing_model.joblib
│   │   └── metrics.json
│   │
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_api.py
│   │   └── test_features.py
│   │
│   ├── Dockerfile
│   ├── requirements.txt
│   └── prepare_dataset.py
│
├── frontend/
│   ├── src/
│   │   ├── main.jsx
│   │   └── style.css
│   ├── package.json
│   └── package-lock.json
│
├── docker-compose.yml
├── .gitignore
├── LICENSE
└── README.md
```

---

## ⚙️ Local Installation

### 1. Clone the repository

```bash
git clone https://github.com/Mohamed-Yassine-216/phishguard-ai.git
cd phishguard-ai
```

### 2. Backend setup

Create and activate a Python virtual environment:

```powershell
cd backend

python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

### 3. Start the API

From the `backend` directory:

```powershell
uvicorn app.main:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

### 4. Start the frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

The frontend will be available at:

```text
http://localhost:5173
```

---

## 🔌 API

### Health Check

```http
GET /health
```

Example response:

```json
{
  "status": "healthy",
  "model": "loaded"
}
```

### URL Prediction

```http
POST /predict
Content-Type: application/json
```

Request:

```json
{
  "url": "https://www.wikipedia.org"
}
```

Response:

```json
{
  "url": "https://www.wikipedia.org",
  "label": "LEGITIMATE",
  "phishing_probability": 0.0001,
  "risk_score": 0.01,
  "risk_level": "LOW"
}
```

---

## 🧪 Testing

The project includes automated API and feature-extraction tests.

Run:

```powershell
cd backend
pytest
```

Current test status:

```text
14 passed
```

The tests cover:

- API root endpoint
- Health endpoint
- Legitimate URL detection
- Phishing URL detection
- URL validation
- IP address detection
- HTTPS detection
- Suspicious keywords
- Suspicious file extensions
- URL shorteners
- `@` symbol detection
- Encoded characters

---

## 🔐 Security Considerations

PhishGuard AI is designed as a **URL analysis and defensive cybersecurity tool**.

The system performs static URL analysis and does not intentionally visit or execute the submitted URL.

Predictions should be treated as an additional security signal rather than an absolute determination that a website is safe or malicious.

---

## 🔮 Future Improvements

Potential future improvements include:

- Real-time threat intelligence integration
- DNS and WHOIS enrichment
- Domain age analysis
- Certificate analysis
- External reputation APIs
- Browser extension integration
- URL scanning history
- Authentication and user accounts
- Production deployment
- More advanced ML models
- Model monitoring and drift detection

---

## 👨‍💻 Author

**Mohamed Yassine Chafra**

Final-Year Cybersecurity Engineering Student

Interested in:

- Cybersecurity
- Threat Detection
- Machine Learning
- Security Automation
- Secure Software Engineering

---

## 📄 License

This project is released under the license included in this repository.

---

⭐ If you find this project useful, consider giving it a star.