from pipelineguard.git_context import _safe_remote


def test_https_userinfo_and_query_are_removed():
    url = "https://alice:ghp_NOT_A_REAL_TOKEN@github.com/owner/repo.git?token=SECRET#private"
    assert _safe_remote(url) == "https://github.com/owner/repo.git"


def test_scp_ssh_userinfo_is_removed():
    assert _safe_remote("git@github.com:owner/repo.git") == "ssh://github.com/owner/repo.git"


def test_local_and_ambiguous_remotes_are_not_exported():
    assert _safe_remote("/home/user/private/repo") is None
    assert _safe_remote("https://alice:secret@github.com/private/token/owner/repo.git") == "https://github.com"


def test_normal_remote_is_preserved_without_credentials():
    assert _safe_remote("https://github.com/owner/repo.git") == "https://github.com/owner/repo.git"
