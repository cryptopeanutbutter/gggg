from pathlib import Path

from utils.hashing import sha256_file, sha256_bytes, aggregate_hash


def test_sha256_file(tmp_path: Path) -> None:
    sample = Path("tests/data/sample.txt")
    expected = sha256_bytes(sample.read_bytes())
    assert sha256_file(sample) == expected


def test_aggregate_hash() -> None:
    values = ["alpha", "beta", "gamma"]
    digest = aggregate_hash(values)
    assert len(digest) == 64
    assert digest == aggregate_hash(values)
