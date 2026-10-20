"""Vanilla and policy-hinted LLM baselines via OpenRouter.

Each cell (model, mode, project, revision) shows the model the single production
file that CWE-Bench-Java's fix_info.csv names (hinted mode may add the file that
holds the configured sink) and asks for findings as JSON. Prompts and hints are
the frozen texts in data/prompts. Each cell is sampled several times (hosted
models are not deterministic even at temperature 0); each sample is one request,
and only transport failures are retried within it, never an answer.
"""
import json
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import config
from .subjects import fix_file, fix_labels, manifest
from .util import read_json, write_json

PROMPTS = config.DATA / "prompts"
MAX_TOKENS = 8000  # same budget as the original CS6215_proj runs
RETRYABLE_HTTP = {408, 429, 500, 502, 503, 504}


def hints():
    return read_json(PROMPTS / "hints.json")


def render_files(files):
    return "\n\n".join("File: {}\n```java\n{}\n```".format(path, text) for path, text in files)


def build_prompt(mode, project, files):
    """``files`` is a list of (repo-relative path, text); the fix file comes first."""
    if mode == "vanilla":
        return (PROMPTS / "vanilla.txt").read_text().format(files=render_files(files[:1]))
    if mode == "hinted":
        template = (PROMPTS / "hinted.txt").read_text()
        return template.format(hint=hints()["hints"][project], files=render_files(files))
    raise ValueError("Unknown mode: " + mode)


def input_files(project, variant, mode):
    spec = manifest()["subjects"][project]
    checkout = config.SUBJECTS / project / variant
    paths = [fix_file(fix_labels(spec["slug"]))]
    if mode == "hinted":
        paths += [p for p in hints()["sink_files"].get(project, []) if p not in paths]
    files = []
    for rel in paths:
        path = checkout / rel
        if not path.is_file():
            raise RuntimeError("Missing {}; run the taie step first to create checkouts".format(path))
        files.append((rel, path.read_text()))
    return files


def request_body(model, prompt):
    return dict(model=model, temperature=0, max_tokens=MAX_TOKENS, reasoning=dict(effort="low"),
                messages=[dict(role="user", content=prompt)])


def call(body, key, timeout=600, attempts=3):
    """POST to OpenRouter; retry only network errors, retryable HTTP codes and empty bodies."""
    data = json.dumps(body).encode()
    last = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(10 * attempt)
        request = urllib.request.Request(config.OPENROUTER_URL, data=data, method="POST", headers={
            "Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            last = "HTTP {}: {}".format(exc.code, exc.read()[:300])
            if exc.code not in RETRYABLE_HTTP:
                break
            continue
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
            last = "{}: {}".format(type(exc).__name__, exc)
            continue
        if "error" in raw and not raw.get("choices"):
            last = "Provider error: " + json.dumps(raw["error"])[:300]
            continue
        return raw, attempt + 1
    raise RuntimeError("OpenRouter request failed after {} attempt(s): {}".format(attempt + 1, last))


def parse_findings(content):
    match = re.search(r"\{.*\}", content.strip(), re.DOTALL)
    if not match:
        raise ValueError("No JSON object in model response")
    findings = json.loads(match.group(0)).get("findings", [])
    if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
        raise ValueError("'findings' must be a list of objects")
    return findings


def is_path_traversal(finding):
    text = (str(finding.get("cwe", "")) + " " + str(finding.get("explanation", ""))).lower()
    return any(word in text for word in hints()["path_traversal_keywords"])


def cwe22_locations(raw):
    """CWE-22 ``(class, method)`` locations from a completed response; raise if unusable."""
    choice = raw["choices"][0]
    if choice.get("finish_reason") != "stop":
        raise ValueError("Incomplete response: finish_reason=" + str(choice.get("finish_reason")))
    content = choice["message"].get("content") or ""
    if not content.strip():
        raise ValueError("Empty response content")
    findings = parse_findings(content)
    locations = sorted({(str(f.get("class", "")).strip(), str(f.get("method", "")).strip())
                        for f in findings if is_path_traversal(f)})
    return [list(loc) for loc in locations if all(loc)], findings


def cell_path(run_dir, short, mode, project, variant, sample):
    return run_dir / "llm" / "{}-{}".format(short, mode) / "{}-{}-s{}.json".format(project, variant, sample)


def run_cell(run_dir, short, mode, project, variant, sample, key):
    out = cell_path(run_dir, short, mode, project, variant, sample)
    body = request_body(config.MODELS[short], build_prompt(mode, project, input_files(project, variant, mode)))
    record = dict(model=body["model"], mode=mode, project=project, variant=variant, sample=sample, request=body)
    started = time.monotonic()
    try:
        raw, attempts = call(body, key)
        record.update(response=raw, attempts=attempts)
    except RuntimeError as exc:
        record["error"] = str(exc)
    record["seconds"] = round(time.monotonic() - started, 2)
    write_json(out, record)
    if "response" in record:
        try:
            status = "{} CWE-22 location(s)".format(len(cwe22_locations(record["response"])[0]))
        except (ValueError, KeyError, IndexError) as exc:
            status = "unusable: {}".format(exc)
    else:
        status = record["error"]
    print("{}-{} {} {} s{}: {} ({}s)".format(short, mode, project, variant, sample, status, record["seconds"]),
          flush=True)


def run(run_dir, models, modes, projects, variants, samples, workers=8, dry_run=False):
    """Request every cell that has no saved record. Each sample is an independent request;
    a saved record (even a failed one) is final and never re-requested."""
    cells = [(s, m, p, v, k) for s in models for m in modes for p in projects for v in variants
             for k in range(1, samples + 1) if not cell_path(run_dir, s, m, p, v, k).is_file()]
    print("{} cell(s) to request".format(len(cells)), flush=True)
    if dry_run:
        for s, m, p, v, k in cells:
            prompt = build_prompt(m, p, input_files(p, v, m))
            print("  {}-{} {} {} s{}: {} prompt chars".format(s, m, p, v, k, len(prompt)))
        return
    key = config.secret("OPENROUTER_API_KEY")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for future in [pool.submit(run_cell, run_dir, *cell, key) for cell in cells]:
            future.result()
