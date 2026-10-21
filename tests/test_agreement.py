"""Tests for the agreement guard: selection, guard filtering, fixed-revision scoring and
both guard checkers (the checker tests need JDK 17 and the Tai-e jar, else they skip)."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from cwe22 import agreement, config, guards, taie

SIG = "<a.Unzip: void extract(java.io.File,java.io.InputStream)>"
FLOW = ("TaintFlow{" + SIG + "[8@L127] name = invokevirtual e.getName()/result -> "
        + SIG + "[37@L148] invokespecial fos.<init>(file)/0}")
CATALOGUE = dict(call_sites=[dict(id=SIG + "#37", declared_target=guards.SINK_TARGET,
                                  resolved_target=guards.SINK_TARGET)])
LABELS = {"p": [{"class": "Unzip", "method": "extract", "file": "src/main/java/a/Unzip.java"}]}


class SelectionTest(unittest.TestCase):
    def test_agreement_else_static(self):
        chosen = agreement.select([("A", "x"), ("B", "y")], [{("A", "x"), ("C", "z")}, set()])
        self.assertEqual(chosen, dict(priority=[("A", "x")], tail=[("B", "y"), ("C", "z")], fallback=False))
        chosen = agreement.select([("A", "x"), ("B", "y")], [{("C", "z")}, set()])
        self.assertEqual(chosen["priority"], [("A", "x"), ("B", "y")])
        self.assertTrue(chosen["fallback"])
        self.assertEqual(agreement.select([], [{("C", "z")}]), dict(priority=[], tail=[("C", "z")], fallback=True))

    def test_guard_sets_aside_only_flows_into_the_protected_sink(self):
        protected = [dict(cls="a.Unzip", method="extract", line=148, checker="canonical")]
        self.assertTrue(guards.guarded(FLOW, protected, CATALOGUE))
        self.assertFalse(guards.guarded(FLOW, [dict(protected[0], line=149)], CATALOGUE))
        self.assertFalse(guards.guarded(FLOW, [dict(protected[0], cls="a.Other")], CATALOGUE))
        other = dict(call_sites=[dict(CATALOGUE["call_sites"][0], resolved_target=None,
                                      declared_target="<java.io.File: void <init>(java.lang.String)>")])
        self.assertFalse(guards.guarded(FLOW, protected, other))
        self.assertFalse(guards.guarded(FLOW, protected, dict(call_sites=[])))

    def test_sink_key_matches_nested_classes_and_constructors(self):
        self.assertEqual(guards.sink_key("a.Out$In", "<init>", "5"), ("a.Out.In", "In", 5))
        self.assertEqual(guards.sink_key("a.Out.In", "In", 5), ("a.Out.In", "In", 5))

    def test_fixed_revision_flag_and_pair_correct(self):
        outputs = {"vulnerable": [("Unzip", "extract"), ("Unzip", "other")], "fixed": [("Unzip", "extract")]}
        load = lambda p, v, s: (outputs[v], None)
        row = agreement.score_arm(load, 1, ["p"], LABELS)[0]["projects"][0]
        self.assertEqual((row["detected"], row["flagged"], row["pair_correct"], row["fixed_reported"]),
                         (True, True, False, 1))
        outputs["fixed"] = [("Unzip", "other")]
        summary = agreement.score_arm(load, 1, ["p"], LABELS)[0]["summary"]
        self.assertEqual((summary["flagged"], summary["pair_correct"]), (0, 1))
        missing = lambda p, v, s: (None, None) if v == "fixed" else (outputs[v], None)
        self.assertFalse(agreement.score_arm(missing, 1, ["p"], LABELS)[0]["summary"]["complete"])

    def test_configs_cover_every_level(self):
        rows = agreement.configs(["qwen", "deepseek"])
        self.assertEqual([c for _, c, _ in rows],
                         ["manual", "h1", "h2a", "h2b-qwen", "h2b-deepseek", "e-qwen-h2b", "e-deepseek-h2b"])


def java_ready():
    try:
        return config.TAIE_JAR.is_file() and bool(taie.java_home())
    except (OSError, RuntimeError, KeyError, subprocess.SubprocessError):
        return False


PATH_PREFIX = """
        java.nio.file.Path r = root.toAbsolutePath().normalize();
        java.nio.file.Path p = r.resolve(name).normalize();
"""
PATH_GUARD = "\n        if (!p.startsWith(r)) { throw new java.io.IOException(); }\n"
PATH_SINK = "\n        new java.io.FileOutputStream(p.toFile());\n"
# (name, protected?, body) for the path template; the CS6215_proj fixtures.
PATH_CASES = [
    ("safe_standard", True, PATH_PREFIX + PATH_GUARD + PATH_SINK),
    ("safe_renamed", True, re.sub(r"\b[pr]\b", lambda m: {"p": "destination", "r": "base"}[m[0]],
                                  PATH_PREFIX + PATH_GUARD + PATH_SINK)),
    ("safe_return", True, PATH_PREFIX + PATH_GUARD.replace("throw new java.io.IOException();", "return;") + PATH_SINK),
    ("safe_parentheses", True, PATH_PREFIX + PATH_GUARD.replace("!p.startsWith(r)", "!((p.startsWith(r)))") + PATH_SINK),
    ("safe_positive_branch", False, PATH_PREFIX + "if (p.startsWith(r)) {" + PATH_SINK + "}\n"),
    ("safe_try_block", False, PATH_PREFIX + "try {" + PATH_GUARD + PATH_SINK + "} finally {}\n"),
    ("unsafe_reversed_guard", False, PATH_PREFIX + PATH_GUARD.replace("!p.startsWith", "p.startsWith") + PATH_SINK),
    ("unsafe_wrong_value", False, PATH_PREFIX + 'java.nio.file.Path q = r.resolve("safe").normalize();\n'
     + PATH_GUARD.replace("!p.", "!q.") + PATH_SINK),
    ("unsafe_not_normalized", False, PATH_PREFIX.replace("r.resolve(name).normalize()", "r.resolve(name)") + PATH_GUARD + PATH_SINK),
    ("unsafe_sink_before_guard", False, PATH_PREFIX + PATH_SINK + PATH_GUARD),
    ("unsafe_reassignment", False, PATH_PREFIX + PATH_GUARD + 'p = r.resolve(name + "/../../outside").normalize();\n' + PATH_SINK),
    ("unsafe_string_prefix", False, PATH_PREFIX + "if (!p.toFile().getCanonicalPath().startsWith(r.toFile().getCanonicalPath()))"
     " { throw new java.io.IOException(); }\n" + PATH_SINK),
    ("unsafe_partial_guard", False, PATH_PREFIX + "if (name.length() < 4) {" + PATH_GUARD + "}\n" + PATH_SINK),
]
DECL = "File file = new File(root, name); String r = root.getCanonicalPath(); String p = file.getCanonicalPath();"
GUARD = "if (!p.startsWith(r + File.separator)) { throw new IOException(); }"
SINK = "FileOutputStream out = new FileOutputStream(file);"
# (name, protected?, body) for the canonical checker; the CS6215_proj adversarial cases.
CANONICAL_CASES = [
    ("safe_direct", True, DECL + GUARD + SINK),
    ("safe_loop", True, "for (String name : names) {" + DECL + GUARD + SINK + "}"),
    ("safe_return", True, DECL + GUARD.replace("throw new IOException();", "return;") + SINK),
    ("bare_prefix", False, DECL + GUARD.replace("r + File.separator", "r") + SINK),
    ("unnormalized", False, DECL.replace("getCanonicalPath", "getAbsolutePath") + GUARD + SINK),
    ("positive_branch", False, DECL + GUARD.replace("!p.startsWith", "p.startsWith") + SINK),
    ("sink_first", False, DECL + SINK + GUARD),
    ("different_file", False, DECL + GUARD + "File other = new File(root, name);" + SINK.replace("(file)", "(other)")),
    ("reassigned_file", False, DECL + GUARD + "file = new File(root, name);" + SINK),
    ("reassigned_root", False, DECL + "root = new File(name);" + GUARD + SINK),
    ("reassigned_canonical", False, DECL + "p = r;" + GUARD + SINK),
    ("conditional_guard", False, DECL + "if (name.isEmpty()) {" + GUARD + "}" + SINK),
    ("caught_rejection", False, DECL + "try {" + GUARD + "} catch (IOException ignored) {}" + SINK),
    ("nonrejecting_branch", False, DECL + GUARD.replace("throw new IOException();", "System.out.println(name);") + SINK),
    ("wrong_boundary", False, DECL + GUARD.replace("File.separator", '"."') + SINK),
    ("extra_condition", False, DECL + GUARD.replace("!p.startsWith(r + File.separator)",
                                                    "!p.startsWith(r + File.separator) && name.isEmpty()") + SINK),
    ("untrusted_root", False, "File root = new File(name);" + DECL + GUARD + SINK),
    ("guard_in_finally", False, DECL + "try {} finally {" + GUARD + "}" + SINK),
]


@unittest.skipUnless(java_ready(), "needs JDK 17 and the Tai-e jar (python3 -m cwe22 setup)")
class CheckerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        java = guards.compile_checkers(taie.java_home(), root / "classes")
        package = root / "src/main/java/t"
        package.mkdir(parents=True)
        (package / "PathCases.java").write_text("package t;\npublic class PathCases {\n" + "".join(
            "public static void {}(java.nio.file.Path root, String name) throws java.io.IOException {{\n{}}}\n".format(n, b)
            for n, _, b in PATH_CASES) + "}\n")
        (package / "CanonicalCases.java").write_text("package t;\nimport java.io.*;\npublic class CanonicalCases {\n" + "".join(
            "void {}({}) throws IOException {{{}}}\n".format(
                n, "String[] names, File root" if n == "safe_loop" else "String name" if n == "untrusted_root"
                else "File root, String name", b) for n, _, b in CANONICAL_CASES) + "}\n")
        cls.result = guards.check(root, [root / "classes"], java)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def contracts(self, checker, cls):
        return {c["method"]: c for c in self.result["contracts"] if c["checker"] == checker and c["cls"] == cls}

    def test_path_template(self):
        found = self.contracts("path", "t.PathCases")
        for name, protected, _ in PATH_CASES:
            with self.subTest(name=name):
                self.assertEqual(found[name]["protects_sink"], protected)
        self.assertEqual(found["unsafe_string_prefix"]["status"], "refuted")

    def test_canonical_checker(self):
        found = self.contracts("canonical", "t.CanonicalCases")
        self.assertEqual(set(found), {n for n, _, _ in CANONICAL_CASES})
        for name, protected, _ in CANONICAL_CASES:
            with self.subTest(name=name):
                self.assertEqual(found[name]["protects_sink"], protected)

    def test_protected_list_is_what_the_filter_uses(self):
        expected = ({("t.PathCases", n) for n, p, _ in PATH_CASES if p}
                    | {("t.CanonicalCases", n) for n, p, _ in CANONICAL_CASES if p})
        self.assertEqual({(p["cls"], p["method"]) for p in self.result["protected"]}, expected)


if __name__ == "__main__":
    unittest.main()
