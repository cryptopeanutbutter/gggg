from pathlib import Path

from scanner.downloads import DownloadCorrelator
from utils.hashing import sha256_file


def test_match_process(tmp_path: Path) -> None:
    downloads_dir = tmp_path / "Downloads"
    downloads_dir.mkdir()
    sample = downloads_dir / "demo.bin"
    sample.write_bytes(b"binary data")
    correlator = DownloadCorrelator(downloads_dir=downloads_dir)
    sha = sha256_file(sample)
    matches = correlator.match_process(sha)
    assert len(matches) == 1
    assert matches[0].path == sample


def test_summary_handles_missing_dir(tmp_path: Path) -> None:
    correlator = DownloadCorrelator(downloads_dir=tmp_path / "missing")
    assert correlator.summary() == []
