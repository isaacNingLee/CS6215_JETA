"""Build each subject revision and run Tai-e taint analysis with its manual policy."""
import os
import re
import shutil
import subprocess
import sys
import time

from . import config
from .scoring import flow_locations
from .subjects import manifest, project_rows
from .util import capture, run_logged, sha256, write_json

BUILD_RECIPE = 1  # bump to force rebuilding every checkout
FLOW_COUNT = re.compile(r"Detected (\d+) taint flow\(s\):")


def java_home():
    if sys.platform == "darwin":
        home = capture(["/usr/libexec/java_home", "-F", "-v", "17"])
    else:
        home = os.environ["JAVA_HOME"]
    version = capture([os.path.join(home, "bin/java"), "-version"])
    if not re.search(r'version "17[."]', version):
        raise RuntimeError("Java 17 is required, found: " + version.splitlines()[0])
    return home


def patched_pom(project, original):
    """The only allowed source edit: zt-zip's Java 1.5/1.6 level, which JDK 17 rejects."""
    if project != "zt-zip":
        return original
    for level in (b"1.5", b"1.6"):
        original = original.replace(b"<source>" + level + b"</source>", b"<source>1.7</source>")
        original = original.replace(b"<target>" + level + b"</target>", b"<target>1.7</target>")
    return original


def checkout(project, variant, commit, url):
    path = config.SUBJECTS / project / variant
    if not (path / ".git").is_dir():
        path.mkdir(parents=True, exist_ok=True)
        for command in (["init", "--quiet"], ["remote", "add", "origin", url],
                        ["fetch", "--quiet", "--depth", "1", "origin", commit],
                        ["checkout", "--quiet", "--detach", commit]):
            subprocess.run(["git", "-C", str(path)] + command, check=True)
    head = capture(["git", "-C", path, "rev-parse", "HEAD"])
    if head != commit:
        raise RuntimeError("{} is at {}, expected {}".format(path, head, commit))
    changed = capture(["git", "-C", path, "diff", "HEAD", "--name-only"]).splitlines()
    if any(name != "pom.xml" for name in changed):
        raise RuntimeError("Unexpected source edits in {}: {}".format(path, changed))
    return path


def build(project, variant, spec, path, jhome, logs):
    """Compile the checkout and copy its runtime dependencies; cached by a stamp file."""
    pom = path / "pom.xml"
    pom.write_bytes(patched_pom(project, subprocess.check_output(["git", "-C", str(path), "show", "HEAD:pom.xml"])))
    stamp = path / "target/cs6215-build.json"
    want = dict(commit=spec[variant], pom_sha256=sha256(pom), recipe=BUILD_RECIPE)
    deps = path / "target/analysis-deps"
    if not (stamp.is_file() and stamp.read_text().strip() == str(want) and
            any((path / "target/classes").rglob("*.class"))):
        print("  building {} {}".format(project, variant), flush=True)
        env = dict(os.environ, JAVA_HOME=jhome, PATH=os.path.join(jhome, "bin") + os.pathsep + os.environ["PATH"])
        command = [config.MAVEN, "-B", "-q", "-Dmaven.test.skip=true", "-Dmaven.javadoc.skip=true"]
        if spec.get("compiler_source_target"):
            level = spec["compiler_source_target"]
            command += ["-Dmaven.compiler.source=" + level, "-Dmaven.compiler.target=" + level]
        copy_deps = ["org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy-dependencies",
                     "-Dmdep.useRepositoryLayout=true", "-DoutputDirectory=" + str(deps)]
        run_logged(command + ["clean", "compile"] + copy_deps + ["-DincludeScope=runtime"],
                   logs / "build.log", cwd=path, env=env)
        for scope in spec.get("extra_dependency_scopes", []):
            run_logged([config.MAVEN, "-B", "-q"] + copy_deps + ["-DincludeScope=" + scope],
                       logs / ("build-" + scope + ".log"), cwd=path, env=env)
        if not any((path / "target/classes").rglob("*.class")):
            raise RuntimeError("Build produced no classes for {} {}".format(project, variant))
        stamp.write_text(str(want) + "\n")
    return [path / "target/classes"] + sorted(deps.rglob("*.jar"))


def taint_config(project, dest):
    """Assemble the shared string transfers plus the project's policy files."""
    dest.mkdir(parents=True, exist_ok=True)
    for folder in (config.DATA / "taie/common", config.DATA / "taie" / project):
        for file in sorted(folder.glob("*.yml")):
            shutil.copy2(file, dest / file.name)
    return dest


def parse_console(text):
    """Return the unique flow lines; fail if the reported count disagrees."""
    count = FLOW_COUNT.search(text)
    flows = sorted({line.strip() for line in text.splitlines() if line.startswith("TaintFlow{")})
    if count is None or int(count.group(1)) != len(flows):
        raise RuntimeError("Missing or inconsistent Tai-e flow report")
    return flows


def compile_adapter(adapter, classpath, jhome, out, log):
    out.mkdir(parents=True, exist_ok=True)
    run_logged([os.path.join(jhome, "bin/javac"), "-g", "--release", "17",
                "-cp", os.pathsep.join(map(str, classpath)), "-d", out, adapter], log, timeout=120)
    return out


def taie_command(jhome, heap, entry, classpath, options, output, launcher=None, properties=()):
    """Tai-e invocation; ``launcher`` replaces ``-jar`` with an explicit class path (plugins)."""
    command = [os.path.join(jhome, "bin/java"), "-Xmx" + heap] + ["-D" + p for p in properties]
    command += ["-cp", launcher, "pascal.taie.Main"] if launcher else ["-jar", config.TAIE_JAR]
    for entry_cp in classpath:
        command += ["-cp", entry_cp]
    command += ["-m", entry]
    for option in options:
        command += ["-a", option]
    return command + ["--output-dir", output]


def project_classes(classes, entry):
    """Class names compiled from the subject's own sources, plus the entry class."""
    names = {p.relative_to(classes).with_suffix("").as_posix().replace("/", ".") for p in classes.rglob("*.class")}
    return sorted(names | {entry})


def analyze(project, variant, spec, classpath, jhome, raw, heap, timeout, adapter=None, policy=None):
    """Run Tai-e once. Defaults: the manual adapter and manual policy of ``project``."""
    adapter = adapter or config.DATA / "adapters" / (spec["entry"] + ".java")
    entry = adapter.stem
    classes = compile_adapter(adapter, classpath, jhome, raw / "adapter", raw / "adapter.log")
    policy = policy or taint_config(project, raw / "config")
    command = taie_command(jhome, heap, entry, [classes] + classpath,
                           ["pta=cs:ci;only-app:false;taint-config:" + str(policy), "cg=algorithm:pta;dump-methods:true"],
                           raw / "tai-e")
    started = time.monotonic()
    run_logged(command, raw / "console.log", cwd=raw, timeout=timeout)
    seconds = round(time.monotonic() - started, 2)
    flows = parse_console((raw / "console.log").read_text(errors="replace"))
    reachable = (raw / "tai-e/reachable-methods.txt").read_text()
    return dict(seconds=seconds, entry=entry, adapter_sha256=sha256(adapter), flows=flows,
                locations=[list(x) for x in flow_locations(flows)],
                target_reachable=spec["reachable"] in reachable,
                target_pair_reported=any(spec["source_match"] in f.split(" -> ")[0] and
                                         spec["sink_match"] in f.split(" -> ")[-1] for f in flows),
                policy_sha256={f.name: sha256(f) for f in sorted(policy.glob("*.yml"))})


def subject(project, variant, jhome, logs):
    """Check out and build one pinned revision; return (checkout, analysis class path)."""
    spec = manifest()["subjects"][project]
    info = project_rows()[spec["slug"]]
    if info["buggy_commit_id"] != spec["vulnerable"] or info["fix_commit_ids"].split(";")[-1] != spec["fixed"]:
        raise RuntimeError("Manifest commits disagree with the dataset for " + project)
    path = checkout(project, variant, spec[variant], info["github_url"])
    return path, build(project, variant, spec, path, jhome, logs)


def run(run_dir, projects, variants, heap="4g", timeout=900, force=False):
    """Analyse each (project, variant); results/<run>/taie/<project>-<variant>.json."""
    subjects = manifest()["subjects"]
    jhome = java_home()
    for project in projects:
        for variant in variants:
            out = run_dir / "taie" / "{}-{}.json".format(project, variant)
            if out.is_file() and not force:
                print("skip {} {} (done)".format(project, variant), flush=True)
                continue
            raw = config.RAW / run_dir.name / "{}-{}".format(project, variant)
            if raw.exists():
                shutil.rmtree(raw)
            result = dict(project=project, variant=variant, commit=subjects[project][variant],
                          taie_sha256=sha256(config.TAIE_JAR), status="failed")
            try:
                _, classpath = subject(project, variant, jhome, raw)
                print("  analysing {} {}".format(project, variant), flush=True)
                result.update(analyze(project, variant, subjects[project], classpath, jhome, raw, heap, timeout),
                              status="completed")
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                result["error"] = "{}: {} (logs: {})".format(type(exc).__name__, exc, raw)
            write_json(out, result)
            print("{} {}: {} {}".format(project, variant, result["status"],
                                        len(result.get("flows", [])) if result["status"] == "completed"
                                        else result["error"]), flush=True)
