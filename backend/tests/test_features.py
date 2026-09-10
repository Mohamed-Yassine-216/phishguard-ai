from app.features import extract_features


def test_ip_detection():
    features = extract_features("http://192.168.1.10/login")
    assert features["has_ip_address"] == 1


def test_https_detection():
    features = extract_features("https://example.com")
    assert features["https_flag"] == 1


def test_suspicious_words():
    features = extract_features(
        "http://example.com/verify/account/login"
    )
    assert features["suspicious_keyword_count"] >= 2


def test_suspicious_file_extension():
    features = extract_features(
        "http://192.168.1.10/malware.exe"
    )
    assert features["suspicious_file_extension"] == 1


def test_url_shortener_detection():
    features = extract_features(
        "https://bit.ly/example"
    )
    assert features["is_shortener_domain"] == 1


def test_at_symbol_detection():
    features = extract_features(
        "https://example.com@evil.com/login"
    )
    assert features["has_at_symbol"] == 1


def test_encoded_character_detection():
    features = extract_features(
        "https://example.com/%2Flogin"
    )
    assert features["has_encoded_characters"] == 1