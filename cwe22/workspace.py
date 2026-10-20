"""Download pinned tools and the dataset into WORK (idempotent)."""
import hashlib
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from . import config
from .subjects import check_dataset, manifest
from .util import sha256


def download(url, dest, expected_sha256):
    if dest.is_file() and sha256(dest) == expected_sha256:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print("Downloading", url, flush=True)
    with tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as tmp:
        with urllib.request.urlopen(url, timeout=300) as response:
            shutil.copyfileobj(response, tmp)
    tmp_path = Path(tmp.name)
    actual = sha256(tmp_path)
    if actual != expected_sha256:
        tmp_path.unlink()
        raise RuntimeError("Checksum mismatch for {}: {}".format(url, actual))
    tmp_path.replace(dest)


def install_maven():
    if config.MAVEN.is_file():
        return
    with urllib.request.urlopen(config.MAVEN_URL + ".sha512", timeout=60) as response:
        expected = response.read().decode().split()[0]
    archive = config.TOOLS / Path(config.MAVEN_URL).name
    config.TOOLS.mkdir(parents=True, exist_ok=True)
    print("Downloading", config.MAVEN_URL, flush=True)
    urllib.request.urlretrieve(config.MAVEN_URL, archive)
    if hashlib.sha512(archive.read_bytes()).hexdigest() != expected:
        archive.unlink()
        raise RuntimeError("Maven checksum mismatch")
    with tarfile.open(archive) as tar:
        # Python 3.9 has no extraction filter; reject absolute or escaping members.
        root = config.TOOLS.resolve()
        for member in tar.getmembers():
            target = (root / member.name).resolve()
            if target != root and root not in target.parents or member.issym() or member.islnk():
                raise RuntimeError("Unsafe archive member: " + member.name)
        tar.extractall(config.TOOLS)
    archive.unlink()


def install_dataset(commit):
    if not (config.DATASET / ".git").is_dir():
        subprocess.run(["git", "clone", "--quiet", config.DATASET_URL, str(config.DATASET)], check=True)
    subprocess.run(["git", "-C", str(config.DATASET), "checkout", "--quiet", "--detach", commit], check=True)
    check_dataset(commit)


def setup():
    download(config.TAIE_URL, config.TAIE_JAR, config.TAIE_SHA256)
    install_maven()
    install_dataset(manifest()["dataset_commit"])
    print("Workspace ready:", config.WORK)
