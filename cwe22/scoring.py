"""Fix-method-location proxy metrics shared by every arm.

The unit is one ``(simple class, method)`` location; overloads merge and a
constructor is named after its class. For a project with N reported locations
of which K are recorded production fix methods:

* detected = K > 0
* FDR = 1 - K/N (undefined for empty output)
* F1 = 2K / (N + K) when K > 0, else 0 (binary project recall, as in IRIS §3.6)

Macro F1 and detection count every project; macro FDR averages nonempty outputs.
These are proxies, not verified vulnerability labels.
"""
import re
import statistics

TAIE_METHOD = re.compile(r"<([^:]+): (\S+) ([^ (]+)\([^)]*\)>")


def taie_location(signature):
    """``<pkg.Outer$Inner: void m(int)>`` -> ``("Inner", "m")``."""
    match = TAIE_METHOD.fullmatch(signature)
    if not match:
        raise ValueError("Cannot parse method signature: " + signature)
    owner, _, name = match.groups()
    simple = owner.rsplit(".", 1)[-1].rsplit("$", 1)[-1]
    return simple, simple if name == "<init>" else name


def flow_endpoints(flow):
    """Enclosing method signatures of the source and sink of one Tai-e flow line."""
    if not flow.startswith("TaintFlow{") or not flow.endswith("}"):
        raise ValueError("Unsupported Tai-e flow: " + flow)
    points = flow[len("TaintFlow{"):-1].split(" -> ")
    if len(points) != 2:
        raise ValueError("Expected one source and one sink: " + flow)
    signatures = []
    for point in points:
        match = TAIE_METHOD.match(point)
        if not match:
            raise ValueError("Cannot parse flow endpoint: " + point)
        signatures.append(match.group(0))
    return signatures


def flow_locations(flows):
    return sorted({taie_location(sig) for flow in flows for sig in flow_endpoints(flow)})


def score(locations, labels):
    """Score a set of ``(class, method)`` locations against fix labels."""
    reported = sorted({tuple(loc) for loc in locations})
    expected = {(r["class"], r["method"]) for r in labels}
    matched = [loc for loc in reported if loc in expected]
    n, k = len(reported), len(matched)
    return dict(reported=n, matched=k, detected=k > 0,
                fdr=1 - k / n if n else None,
                f1=2 * k / (n + k) if k else 0.0,
                matched_locations=[list(m) for m in matched])


def aggregate(rows):
    """Macro summary over per-project rows; incomplete if any project is unscored."""
    scored = [r for r in rows if r.get("status") == "scored"]
    result = dict(projects=len(rows), scored=len(scored),
                  complete=bool(rows) and len(scored) == len(rows),
                  detected=None, macro_fdr=None, macro_f1=None, fdr_projects=None)
    if result["complete"]:
        fdrs = [r["fdr"] for r in scored if r["fdr"] is not None]
        result.update(detected=sum(r["detected"] for r in scored),
                      macro_fdr=statistics.mean(fdrs) if fdrs else None,
                      macro_f1=statistics.mean(r["f1"] for r in scored),
                      fdr_projects=len(fdrs))
    return result
