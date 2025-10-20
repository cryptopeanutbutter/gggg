"""Hashing helpers and educational dehashing utilities."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def aggregate_hash(values: Iterable[str]) -> str:
    hasher = hashlib.sha256()
    for value in values:
        hasher.update(value.encode("utf-8"))
    return hasher.hexdigest()


@dataclass(frozen=True)
class DehashMatch:
    """Result for a resolved hash value."""

    algorithm: str
    plaintext: str
    source: str


class MultiDehasher:
    """Deterministic multi-algorithm dehasher for educational use."""

    SUPPORTED_ALGORITHMS: Mapping[str, str] = {
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
    }

    def __init__(self, candidates: Iterable[str] | None = None, source: str = "default") -> None:
        self._candidate_sources: Dict[str, str] = {}
        self._hash_cache: Dict[str, MutableMapping[str, List[str]]] = {
            name: {} for name in self.SUPPORTED_ALGORITHMS
        }
        if candidates:
            self.add_candidates(candidates, source=source)

    @staticmethod
    def _normalise_candidate(value: str) -> str:
        return value.strip()

    def _hasher(self, algorithm: str):
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        return getattr(hashlib, self.SUPPORTED_ALGORITHMS[algorithm])

    def _generate_variants(self, value: str) -> Iterable[str]:
        seeds = {
            value,
            value.lower(),
            value.upper(),
            value.title(),
        }
        variants = set()
        for seed in seeds:
            if not seed:
                continue
            variants.add(seed)
            if not seed[-1].isdigit():
                variants.add(f"{seed}123")
                variants.add(f"{seed}!")
        return variants

    def add_candidates(self, candidates: Iterable[str], *, source: str = "manual") -> int:
        """Register plaintext candidates for educational dehashing."""

        added = 0
        for candidate in candidates:
            base = self._normalise_candidate(candidate)
            if not base:
                continue
            for value in self._generate_variants(base):
                if value in self._candidate_sources:
                    continue
                self._candidate_sources[value] = source
                for algorithm in self.SUPPORTED_ALGORITHMS:
                    digest = self._hasher(algorithm)(value.encode("utf-8")).hexdigest()
                    bucket = self._hash_cache[algorithm].setdefault(digest, [])
                    if value not in bucket:
                        bucket.append(value)
                added += 1
        return added

    def load_wordlist(self, path: Path, *, source: str | None = None) -> int:
        """Load candidates from a UTF-8 wordlist file."""

        words = []
        try:
            words = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return 0
        return self.add_candidates(words, source=source or path.name)

    def dehash_many(
        self,
        hashes: Sequence[str],
        algorithms: Sequence[str] | None = None,
    ) -> Dict[str, List[DehashMatch]]:
        """Resolve hashes using known candidates for the selected algorithms."""

        requested_algorithms = [algo.lower() for algo in (algorithms or self.SUPPORTED_ALGORITHMS.keys())]
        invalid = [algo for algo in requested_algorithms if algo not in self.SUPPORTED_ALGORITHMS]
        if invalid:
            raise ValueError(f"Unsupported algorithms requested: {', '.join(invalid)}")

        results: Dict[str, List[DehashMatch]] = {}
        for raw_hash in hashes:
            value = raw_hash.strip().lower()
            if not value:
                continue
            matches: List[DehashMatch] = []
            for algorithm in requested_algorithms:
                for candidate in self._hash_cache[algorithm].get(value, []):
                    source = self._candidate_sources.get(candidate, "unknown")
                    matches.append(DehashMatch(algorithm=algorithm, plaintext=candidate, source=source))
            if matches:
                results[value] = matches
        return results
