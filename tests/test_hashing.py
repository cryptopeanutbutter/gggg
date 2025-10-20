from pathlib import Path

from utils.hashing import (
    DehashMatch,
    MultiDehasher,
    aggregate_hash,
    sha256_bytes,
    sha256_file,
)


def test_sha256_file(tmp_path: Path) -> None:
    sample = Path("tests/data/sample.txt")
    expected = sha256_bytes(sample.read_bytes())
    assert sha256_file(sample) == expected


def test_aggregate_hash() -> None:
    values = ["alpha", "beta", "gamma"]
    digest = aggregate_hash(values)
    assert len(digest) == 64
    assert digest == aggregate_hash(values)


def test_multi_dehasher_matches(tmp_path: Path) -> None:
    candidates = ["alpha", "bravo", "charlie"]
    hasher = MultiDehasher(candidates, source="test")
    hashes = [
        sha256_bytes(b"alpha"),
        sha256_bytes(b"bravo"),
        sha256_bytes(b"unmatched"),
    ]
    results = hasher.dehash_many(hashes, ["sha256"])
    assert hashes[0].lower() in results
    alpha_matches = results[hashes[0].lower()]
    assert any(isinstance(entry, DehashMatch) and entry.plaintext == "alpha" for entry in alpha_matches)

    # Loading additional wordlists should increase coverage
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("delta\n")
    added = hasher.load_wordlist(wordlist, source="wordlist")
    assert added >= 1
    delta_hash = sha256_bytes(b"delta")
    delta_results = hasher.dehash_many([delta_hash], ["sha256"])
    assert delta_results[delta_hash.lower()][0].source == "wordlist"

    mutated = sha256_bytes(b"CHARLIE123")
    mutated_results = hasher.dehash_many([mutated], ["sha256"])
    assert mutated.lower() in mutated_results
    assert any(match.plaintext.lower() == "charlie123" for match in mutated_results[mutated.lower()])
