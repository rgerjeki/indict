import pytest

from indict.indicators import DetectionError, detect, host_of, refang
from indict.models import IndicatorType

MD5 = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test file md5


@pytest.mark.parametrize(
    "value, expected_type, expected_norm",
    [
        ("8.8.8.8", IndicatorType.IP, "8.8.8.8"),
        ("2606:4700:4700::1111", IndicatorType.IP, "2606:4700:4700::1111"),
        ("Example.COM", IndicatorType.DOMAIN, "example.com"),
        ("*.sub.example.com", IndicatorType.DOMAIN, "sub.example.com"),
        ("example.com.", IndicatorType.DOMAIN, "example.com"),
        (MD5, IndicatorType.HASH, MD5),
        ("https://Example.com/Path?q=1", IndicatorType.URL, "https://example.com/Path?q=1"),
    ],
)
def test_detect_classifies_and_normalizes(value, expected_type, expected_norm):
    itype, norm = detect(value)
    assert itype is expected_type
    assert norm == expected_norm


def test_detect_refangs_defanged_url():
    itype, norm = detect("hxxps://evil[.]com/a")
    assert itype is IndicatorType.URL
    assert norm == "https://evil.com/a"


def test_refang_handles_bracket_dots():
    assert refang("evil[.]com") == "evil.com"


def test_hash_length_disambiguation():
    # 40 hex chars is sha1, 64 is sha256
    assert detect("a" * 40)[0] is IndicatorType.HASH
    assert detect("a" * 64)[0] is IndicatorType.HASH
    # 50 hex chars is not a real hash length -> not a hash
    assert detect("da39a3ee5e6b4b0d3255bfef95601890afd80709")[0] is IndicatorType.HASH


def test_detect_rejects_garbage():
    with pytest.raises(DetectionError):
        detect("not an indicator!!")
    with pytest.raises(DetectionError):
        detect("")


def test_host_of():
    assert host_of("https://sub.example.com/x") == "sub.example.com"
    assert host_of("not-a-url") is None
