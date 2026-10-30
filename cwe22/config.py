"""Paths, pinned tool versions and secret loading.

Two locations are used:

* ``ROOT`` is this repository (code, inputs and compact results; synced by OneDrive).
* ``WORK`` holds everything large and re-downloadable: tools, the CWE-Bench-Java
  dataset, project checkouts, Maven build output and raw Tai-e output. It lives
  outside OneDrive by default and can be moved with the ``CS6215_WORK`` variable.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RESULTS = ROOT / "results"

WORK = Path(os.environ.get("CS6215_WORK", Path.home() / "cs6215-work")).expanduser()
TOOLS = WORK / "tools"
DATASET = WORK / "cwe-bench-java"
SUBJECTS = WORK / "subjects"
RAW = WORK / "raw"

PROJECTS = ["zip4j", "zt-zip", "spark", "plexus-archiver", "plexus-utils", "mpxj"]
VARIANTS = ["vulnerable", "fixed"]

TAIE_VERSION = "0.5.4"
TAIE_JAR = TOOLS / "tai-e-all-{}.jar".format(TAIE_VERSION)
TAIE_URL = "https://github.com/pascal-lab/Tai-e/releases/download/v{0}/tai-e-all-{0}.jar".format(TAIE_VERSION)
TAIE_SHA256 = "703d1750b66e8e621d628ac93b07a21315db795b3a1e2224001ad09190c1e4be"

MAVEN_VERSION = "3.9.8"
MAVEN_URL = ("https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/{0}/"
             "apache-maven-{0}-bin.tar.gz").format(MAVEN_VERSION)
MAVEN = TOOLS / "apache-maven-{}".format(MAVEN_VERSION) / "bin/mvn"

DATASET_URL = "https://github.com/iris-sast/cwe-bench-java.git"

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
# Short names keep result paths brief; values are OpenRouter model IDs.
MODELS = {
    "qwen": "qwen/qwen3-coder-30b-a3b-instruct",
    "deepseek": "deepseek/deepseek-v4-pro",
}
MODES = ["vanilla", "hinted"]
SAMPLES = 3  # independent LLM requests per cell
# Fixed max_tokens per request, as the saved runs used them. The readers and every hint-relaxation
# step used 8,000 for both models. The later blind-checklist writer and LLMDFA give DeepSeek 16,000,
# since its reasoning tokens count against the budget and at 8,000 it often stopped before answering.
MAX_TOKENS = {"qwen": 8000, "deepseek": 8000}
LONG_MAX_TOKENS = {"qwen": 8000, "deepseek": 16000}


def max_tokens(model, long=False):
    """Budget for an OpenRouter model ID (``long``: the checklist writer's and LLMDFA's)."""
    budgets = LONG_MAX_TOKENS if long else MAX_TOKENS
    return next(budgets[short] for short, name in MODELS.items() if name == model)


def require_data():
    """``data/`` is distributed separately from the code (it is not in git)."""
    if not (DATA / "subjects.json").is_file():
        raise RuntimeError("Missing {}: download the data/ folder and place it at {}".format(DATA, ROOT))


def load_env(path=ROOT / ".env"):
    """Load KEY=VALUE lines from ``.env`` without overriding the real environment."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def secret(name):
    load_env()
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError("{} is not set; add it to {} (see .env.example)".format(name, ROOT / ".env"))
    return value
