import math
import re
from collections import Counter
from urllib.parse import urlparse


POPULAR_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
}

COMMON_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "urlz.fr",
    "shorten.is",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "bank",
    "payment",
    "wallet",
    "recover",
    "unlock",
    "authenticate",
}


def calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def parse_url(url: str):
    """Parse a URL safely."""
    value = str(url).strip()

    if not value.startswith(("http://", "https://")):
        value = "http://" + value

    return urlparse(value)


def extract_dataset_features(url: str) -> dict:
    """
    Extract URL features used by the phishing detection model.

    The feature set combines:
    - lexical URL characteristics
    - domain characteristics
    - path characteristics
    - suspicious-pattern indicators
    """

    parsed = parse_url(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = str(url).strip()

    # Remove common www prefix for domain calculations.
    domain = hostname.lower()
    if domain.startswith("www."):
        domain = domain[4:]

    # ---------------------------------------------------------------
    # Basic lexical features
    # ---------------------------------------------------------------

    url_length = len(full_url)

    has_ip_address = int(
        bool(
            re.fullmatch(
                r"(?:\d{1,3}\.){3}\d{1,3}",
                hostname,
            )
        )
    )

    dot_count = full_url.count(".")

    https_flag = int(parsed.scheme.lower() == "https")

    url_entropy = calculate_entropy(full_url)

    token_count = len(
        [
            token
            for token in re.split(r"[/?:=&._\-]+", full_url)
            if token
        ]
    )

    # ---------------------------------------------------------------
    # Domain features
    # ---------------------------------------------------------------

    domain_parts = [part for part in hostname.split(".") if part]

    # Exclude the TLD from the subdomain calculation.
    subdomain_count = max(0, len(domain_parts) - 2)

    domain_name_length = len(domain)

    has_hyphen_in_domain = int("-" in domain)

    tld = ""

    if "." in domain:
        tld = domain.rsplit(".", 1)[-1]

    tld_length = len(tld)

    tld_popularity = int(tld in POPULAR_TLDS)

    domain_entropy = calculate_entropy(domain)

    # ---------------------------------------------------------------
    # Path / query features
    # ---------------------------------------------------------------

    query_param_count = 0

    if query:
        query_param_count = len(
            [
                item
                for item in query.split("&")
                if item
            ]
        )

    path_length = len(path)

    path_segments = [
        segment
        for segment in path.split("/")
        if segment
    ]

    path_segment_count = len(path_segments)

    # ---------------------------------------------------------------
    # Character-based features
    # ---------------------------------------------------------------

    number_of_digits = sum(character.isdigit() for character in full_url)

    numeric_percentage = (
        (number_of_digits / len(full_url)) * 100
        if full_url
        else 0.0
    )

    # ---------------------------------------------------------------
    # Suspicious structural indicators
    # ---------------------------------------------------------------

    suspicious_file_extension = int(
        bool(
            re.search(
                r"\.(?:exe|scr|zip|rar|7z|msi|bat|cmd|ps1|js|jar|apk|crx|lnk|docm|xlsm|pdf\.lnk|php|asp|aspx|jsp|sh|bin)$",
                path.lower(),
            )
        )
    )

    has_port = int(parsed.port is not None)

    has_encoded_characters = int(
        bool(re.search(r"%[0-9a-fA-F]{2}", full_url))
    )

    has_at_symbol = int("@" in full_url)

    has_double_slash_in_path = int("//" in path)

    # ---------------------------------------------------------------
    # Suspicious keyword features
    # ---------------------------------------------------------------

    lowercase_url = full_url.lower()

    suspicious_keyword_count = sum(
        1
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lowercase_url
    )

    has_suspicious_keyword = int(suspicious_keyword_count > 0)

    # ---------------------------------------------------------------
    # URL shortener feature
    # ---------------------------------------------------------------

    is_shortener_domain = int(
        domain in COMMON_SHORTENER_DOMAINS
    )

    # ---------------------------------------------------------------
    # Return all features
    # ---------------------------------------------------------------

    return {
        "url_length": url_length,
        "has_ip_address": has_ip_address,
        "dot_count": dot_count,
        "https_flag": https_flag,
        "url_entropy": url_entropy,
        "token_count": token_count,
        "subdomain_count": subdomain_count,
        "query_param_count": query_param_count,
        "tld_length": tld_length,
        "path_length": path_length,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "number_of_digits": number_of_digits,
        "tld_popularity": tld_popularity,
        "suspicious_file_extension": suspicious_file_extension,
        "domain_name_length": domain_name_length,
        "percentage_numeric_chars": numeric_percentage,

        # New features
        "domain_entropy": domain_entropy,
        "path_segment_count": path_segment_count,
        "has_port": has_port,
        "has_encoded_characters": has_encoded_characters,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_in_path": has_double_slash_in_path,
        "suspicious_keyword_count": suspicious_keyword_count,
        "has_suspicious_keyword": has_suspicious_keyword,
        "is_shortener_domain": is_shortener_domain,
    }


def extract_features(url: str) -> dict:
    """Backward-compatible feature extraction function."""
    return extract_dataset_features(url)