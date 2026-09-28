from pathlib import Path


def test_repo_paths_are_not_hardcoded_to_user_home():
    from config import APP_ROOT, DATA_DIR

    assert APP_ROOT == Path(__file__).resolve().parents[1]
    assert str(DATA_DIR).startswith(str(APP_ROOT))
    assert "/home/claude" not in str(DATA_DIR)
