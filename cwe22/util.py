"""Small shared helpers: JSON/CSV I/O, hashing and subprocess wrappers."""
import csv
import hashlib
import json
import subprocess


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def read_csv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def capture(command, cwd=None):
    """Run a command and return its stripped stdout+stderr."""
    return subprocess.check_output([str(x) for x in command], cwd=cwd, text=True,
                                   stderr=subprocess.STDOUT).strip()


def run_logged(command, log, cwd=None, env=None, timeout=1800):
    """Run a command with output written to ``log``; raise on failure."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as stream:
        subprocess.run([str(x) for x in command], cwd=cwd, env=env, timeout=timeout,
                       stdout=stream, stderr=subprocess.STDOUT, check=True)
