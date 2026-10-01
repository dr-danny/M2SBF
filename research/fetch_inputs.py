"""Download only locked public inputs and verify bytes before making them available.

python -m research.fetch_inputs --dest research-data
No authentication, upload, auto-update, or downloaded-code execution occurs.
"""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ALLOWED_HOSTS = {"raw.githubusercontent.com", "codeload.github.com", "github.com"}


def safe_path(root, relative):
    root = Path(root).resolve()
    result = (root / relative).resolve()
    if not result.is_relative_to(root) or result == root:
        raise ValueError(f"Unsafe destination path: {relative}")
    return result


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch_locked(lock, destination):
    for item in lock["files"]:
        parsed = urlparse(item["url"])
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or parsed.username or parsed.password:
            raise ValueError("Only locked HTTPS URLs on official GitHub delivery hosts are allowed")
        output = safe_path(destination, item["path"])
        if output.exists():
            if output.stat().st_size != item["bytes"] or sha256_file(output) != item["sha256"]:
                raise ValueError(f"Existing input differs from lock: {item['path']}; preserve it and use a new destination")
            print(f"verified {item['role']}")
            continue
        output.parent.mkdir(parents=True, exist_ok=True)
        partial = output.with_name(output.name + ".partial")
        if partial.exists():
            raise ValueError(f"Existing partial file: {partial}; inspect it before retrying")
        request = Request(item["url"], headers={"User-Agent": "M2SBF-research/1.0"})
        try:
            size = 0
            with urlopen(request, timeout=120) as response, partial.open("xb") as stream:
                if urlparse(response.geturl()).scheme != "https":
                    raise ValueError("Refusing a non-HTTPS redirect")
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > item["bytes"]:
                        raise ValueError("Download exceeds locked byte count")
                    stream.write(block)
            if size != item["bytes"] or sha256_file(partial) != item["sha256"]:
                raise ValueError(f"Downloaded bytes fail lock: {item['role']}")
            partial.replace(output)
            print(f"downloaded and verified {item['role']}")
        except Exception:
            if partial.exists():
                partial.unlink()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path(__file__).with_name("input-lock.json"))
    parser.add_argument("--dest", type=Path, required=True)
    args = parser.parse_args()
    fetch_locked(json.loads(args.lock.read_text()), args.dest)


if __name__ == "__main__":
    main()
