from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root():
    response = client.get("/")
    assert response.status_code == 200

    data = response.json()
    assert data["name"] == "PhishGuard AI"
    assert data["status"] == "online"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert data["model"] == "loaded"


def test_legitimate_url():
    response = client.post(
        "/predict",
        json={"url": "https://www.wikipedia.org"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["label"] == "LEGITIMATE"
    assert 0 <= data["phishing_probability"] <= 1
    assert data["risk_level"] in {"LOW", "MEDIUM", "HIGH"}


def test_phishing_url():
    response = client.post(
        "/predict",
        json={"url": "http://117.72.70.169/xl_ext_chrome.crx"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["label"] == "PHISHING"
    assert data["phishing_probability"] > 0.5
    assert data["risk_level"] == "HIGH"


def test_empty_url():
    response = client.post(
        "/predict",
        json={"url": ""},
    )

    assert response.status_code == 422


def test_url_with_spaces():
    response = client.post(
        "/predict",
        json={"url": "https://example.com/test page"},
    )

    assert response.status_code == 422


def test_url_too_long():
    long_url = "https://example.com/" + ("a" * 2050)

    response = client.post(
        "/predict",
        json={"url": long_url},
    )

    assert response.status_code == 422