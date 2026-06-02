from sentinelforge.redaction import mask_secret, redact_text


def test_mask_secret_keeps_edges():
    assert mask_secret("sk_live_1234567890abcdef").startswith("sk_liv")
    assert mask_secret("sk_live_1234567890abcdef").endswith("cdef")
    assert "1234567890" not in mask_secret("sk_live_1234567890abcdef")


def test_redact_text_masks_common_assignment():
    text = "API_KEY=sk_live_1234567890abcdef"
    redacted = redact_text(text)
    assert "1234567890" not in redacted
    assert "API_KEY=" in redacted
