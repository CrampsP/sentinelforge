from sentinelforge.targeting import TargetKind, classify_target, validate_dynamic_target


def test_classifies_local_path_and_localhost_url(tmp_path):
    assert classify_target(str(tmp_path)).kind == TargetKind.LOCAL_PATH
    assert classify_target("http://localhost:8000").kind == TargetKind.LOCALHOST_URL
    assert classify_target("http://127.0.0.1:8000").kind == TargetKind.LOCALHOST_URL


def test_blocks_public_dynamic_target_without_authorization_flags():
    decision = validate_dynamic_target("https://example.com", i_am_authorized=False, allow_public_target=False)

    assert not decision.allowed
    assert "public" in decision.reason.lower()


def test_allows_public_dynamic_target_only_with_explicit_authorization_flags():
    decision = validate_dynamic_target("https://example.com", i_am_authorized=True, allow_public_target=True)

    assert decision.allowed
