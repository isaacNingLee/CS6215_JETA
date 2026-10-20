"""Program catalogue: Tai-e pointer analysis with no taint policy, exporting the
reachable project methods and their call sites (java/MethodCataloguePlugin.java).

It reads no fix label, no policy and makes no LLM call. Candidate sources and the
source-selection payload are derived from it.
"""
import os
from pathlib import Path

from . import config
from .taie import compile_adapter, project_classes, taie_command
from .util import read_json, run_logged, sha256, write_json

PLUGIN = Path(__file__).resolve().parent / "java/MethodCataloguePlugin.java"
WINDOW = 5  # source lines shown on each side of a call site


def attach_source(catalogue, checkout, adapter):
    """Add +/-WINDOW line source windows to call sites; windows are not program slices."""
    cache = {}

    def lines(cls):
        outer = cls.split("$")[0]
        path = adapter if outer == adapter.stem else checkout / "src/main/java" / (outer.replace(".", "/") + ".java")
        if path not in cache:
            cache[path] = (path.read_text(errors="replace").splitlines(), path.name) if path.is_file() else None
        return cache[path]

    methods = {m["signature"]: m for m in catalogue["methods"]}
    for call in catalogue["call_sites"]:
        source = lines(methods[call["caller"]]["declaring_class"])
        call["source_context"] = None
        if source and 0 < call["line"] <= len(source[0]):
            text, name = source
            start, end = max(1, call["line"] - WINDOW), min(len(text), call["line"] + WINDOW)
            call["source_context"] = dict(file=name, start_line=start, end_line=end, text="\n".join(
                "{}: {}".format(i, text[i - 1]) for i in range(start, end + 1)))
    return catalogue


def build(checkout, classpath, adapter, raw, jhome, heap="4g", timeout=900):
    """Catalogue of one revision under one entry program; cached in ``raw``."""
    out = raw / "catalogue.json"
    stamp = dict(adapter_sha256=sha256(adapter), plugin_sha256=sha256(PLUGIN), taie_sha256=sha256(config.TAIE_JAR))
    if out.is_file() and read_json(out).get("stamp") == stamp:
        return read_json(out)
    entry = adapter.stem
    plugin = raw / "plugin"
    run_logged([os.path.join(jhome, "bin/javac"), "--release", "17", "-cp", config.TAIE_JAR, "-d", plugin, PLUGIN],
               raw / "plugin.log", timeout=120)
    classes = compile_adapter(adapter, classpath, jhome, raw / "adapter", raw / "adapter.log")
    (raw / "classes.txt").write_text("\n".join(project_classes(classpath[0], entry)) + "\n")
    command = taie_command(jhome, heap, entry, [classes] + classpath,
                           ["pta=cs:ci;only-app:false;plugins:[cs6215.MethodCataloguePlugin]",
                            "cg=algorithm:pta;dump-methods:true"], raw / "tai-e",
                           launcher=os.pathsep.join([str(plugin), str(config.TAIE_JAR)]),
                           properties=["catalogue.projectClasses=" + str(raw / "classes.txt"),
                                       "catalogue.output=" + str(raw / "raw-catalogue.json")])
    run_logged(command, raw / "console.log", cwd=raw, timeout=timeout)
    catalogue = attach_source(read_json(raw / "raw-catalogue.json"), checkout, adapter)
    if not catalogue["call_sites"]:
        raise RuntimeError("No project call sites were exported: " + str(raw))
    catalogue["stamp"] = stamp
    write_json(out, catalogue)
    return catalogue
