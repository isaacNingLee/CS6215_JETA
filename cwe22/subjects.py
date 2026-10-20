"""Subject manifest and CWE-Bench-Java fix-method labels."""
import subprocess

from .config import DATA, DATASET
from .util import read_csv, read_json


def manifest():
    return read_json(DATA / "subjects.json")


def check_dataset(commit):
    """Refuse to score against labels that differ from the pinned dataset revision."""
    head = subprocess.check_output(["git", "-C", str(DATASET), "rev-parse", "HEAD"], text=True).strip()
    if head != commit:
        raise RuntimeError("Dataset is at {}, expected {}".format(head, commit))
    for name in ("project_info.csv", "fix_info.csv"):
        pinned = subprocess.check_output(["git", "-C", str(DATASET), "show", commit + ":data/" + name])
        if (DATASET / "data" / name).read_bytes() != pinned:
            raise RuntimeError("Dataset file has local changes: data/" + name)


def project_rows():
    return {row["project_slug"]: row for row in read_csv(DATASET / "data/project_info.csv")}


def fix_labels(slug):
    """Production (non-test) fix methods recorded for one dataset case."""
    labels = [r for r in read_csv(DATASET / "data/fix_info.csv")
              if r["project_slug"] == slug and "src/test" not in r["file"]]
    if not labels:
        raise RuntimeError("No production fix labels for " + slug)
    return labels


def fix_file(labels):
    """The single production file containing the fix (the LLM readers' input)."""
    files = sorted({label["file"] for label in labels})
    if len(files) != 1:
        raise RuntimeError("Expected one production fix file, found " + str(files))
    return files[0]
