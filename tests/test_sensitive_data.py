from firewall.detectors.sensitive_data import SensitiveDataDetector
from firewall.core.events import Actor, SecurityEvent


def _det(text: str, out: bool = False):
    d = SensitiveDataDetector()
    ev = SecurityEvent(actor=Actor(user_id="u"),
                       input_text="" if out else text,
                       output_text=text if out else "")
    return d.scan(ev)


def test_openai_key():
    ds = _det("token=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX")
    assert any(x.technique == "openai_api_key" for x in ds)


def test_aws_key_pair():
    text = "AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    ds = _det(text)
    assert any(x.technique == "aws_access_key_id" for x in ds)


def test_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...abcdefghij\n-----END RSA PRIVATE KEY-----"
    ds = _det(text)
    assert any(x.technique in ("private_key_pem", "gcp_service_account") for x in ds)


def test_luhn_credit_card_valid():
    ds = _det("Card: 4111 1111 1111 1111")
    assert any(x.technique == "credit_card" for x in ds)


def test_luhn_credit_card_invalid_no_fp():
    ds = _det("Random digits 1234 5678 9012 3456")
    assert not any(x.technique == "credit_card" for x in ds)


def test_benign_no_secret_lookalike():
    ds = _det("This is a placeholder like ghp_XXXXXXXXXXXX (do not use).")
    assert not any(x.subcategory == "secret" for x in ds)


def test_pii_email():
    ds = _det("Contact: alice@example.com")
    assert any(x.technique == "email" for x in ds)


def test_redaction():
    d = SensitiveDataDetector()
    out = d.redact("token=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQ email=alice@example.com")
    assert "[REDACTED" in out
    assert "alice@example.com" not in out
