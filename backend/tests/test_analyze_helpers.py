from app.api.routes.analyze import (
    _derive_repo_clone_url,
    _manifest_touched,
    _normalize_status,
)


def test_derive_repo_clone_url_handles_repo_and_pr_urls():
    assert _derive_repo_clone_url("owner/repo") == "https://github.com/owner/repo"
    assert (
        _derive_repo_clone_url("https://github.com/owner/repo/pull/42")
        == "https://github.com/owner/repo"
    )
    assert (
        _derive_repo_clone_url("https://github.com/owner/repo/")
        == "https://github.com/owner/repo"
    )


def test_manifest_touched_detects_dependency_files():
    files = [
        "src/main.py",
        "requirements.txt",
        "frontend/package-lock.json",
    ]
    assert _manifest_touched(files) is True
    assert _manifest_touched(["src/app.py", "README.md"]) is False


def test_normalize_status_maps_error_to_failed():
    assert _normalize_status("success") == "success"
    assert _normalize_status("skipped") == "skipped"
    assert _normalize_status("error") == "failed"
    assert _normalize_status("anything-else") == "success"
