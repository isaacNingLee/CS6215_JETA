import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.nio.file.*;
import java.util.*;

/**
 * Parse only. For each requested (file, simple class, method), the source text of the method
 * (every overload; a constructor when the method is the class name) together with its class's
 * fields, constructors and the methods of the same class it calls by simple name (one hop).
 * Usage: MethodContext request.json; request = [{"file", "class", "method"}]. Prints a JSON list
 * with one row per request: {"file", "class", "method", "members": [{"role", "line", "text"}]};
 * "members" is empty when the class has no such method.
 */
public class MethodContext {
    public static void main(String[] args) throws Exception {
        ObjectMapper json = new ObjectMapper();
        List<Map<String, String>> requests = Arrays.asList(json.readValue(Path.of(args[0]).toFile(), Map[].class));
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        Map<String, CompilationUnitTree> units = new HashMap<>();
        Map<String, String> sources = new HashMap<>();
        Map<String, SourcePositions> positions = new HashMap<>();
        List<Object> output = new ArrayList<>();
        for (Map<String, String> request : requests) {
            String file = request.get("file"), cls = request.get("class"), method = request.get("method");
            if (!units.containsKey(file)) {
                DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
                StandardJavaFileManager fm = compiler.getStandardFileManager(diagnostics, null, null);
                JavacTask task = (JavacTask) compiler.getTask(null, fm, diagnostics, List.of("-proc:none"), null,
                        fm.getJavaFileObjects(file));
                units.put(file, task.parse().iterator().next());
                positions.put(file, Trees.instance(task).getSourcePositions());
                sources.put(file, Files.readString(Path.of(file)));
            }
            CompilationUnitTree unit = units.get(file);
            SourcePositions pos = positions.get(file);
            String source = sources.get(file);
            List<Object> members = new ArrayList<>();
            new TreeScanner<Void, Void>() {
                public Void visitClass(ClassTree c, Void p) {
                    if (!c.getSimpleName().contentEquals(cls)) return super.visitClass(c, p);
                    List<MethodTree> methods = new ArrayList<>();
                    for (Tree m : c.getMembers()) if (m instanceof MethodTree x) methods.add(x);
                    boolean ctor = method.equals(cls);
                    List<MethodTree> targets = methods.stream().filter(m -> ctor ? m.getName().contentEquals("<init>")
                            : m.getName().contentEquals(method)).toList();
                    if (targets.isEmpty()) return super.visitClass(c, p);
                    Set<String> called = new HashSet<>();
                    for (MethodTree m : targets) new TreeScanner<Void, Void>() {
                        public Void visitClass(ClassTree x, Void v) { return null; }
                        public Void visitMethodInvocation(MethodInvocationTree x, Void v) {
                            ExpressionTree s = x.getMethodSelect();
                            if (s instanceof IdentifierTree i) called.add(i.getName().toString());
                            else if (s instanceof MemberSelectTree ms && ms.getExpression() instanceof IdentifierTree b
                                    && b.getName().contentEquals("this")) called.add(ms.getIdentifier().toString());
                            return super.visitMethodInvocation(x, v);
                        }
                    }.scan(m, null);
                    for (Tree m : c.getMembers()) {
                        String role = null;
                        if (m instanceof VariableTree) role = "field";
                        else if (m instanceof MethodTree x) {
                            if (targets.contains(x)) role = "method under review";
                            else if (x.getName().contentEquals("<init>")) role = "constructor";
                            else if (called.contains(x.getName().toString())) role = "called method";
                        }
                        if (role == null) continue;
                        long start = pos.getStartPosition(unit, m), end = pos.getEndPosition(unit, m);
                        if (start < 0 || end < start) continue;
                        // Include the Javadoc/annotations-free member text with its leading indentation.
                        int lineStart = source.lastIndexOf('\n', (int) start - 1) + 1;
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("role", role);
                        row.put("line", unit.getLineMap().getLineNumber(start));
                        row.put("text", source.substring(lineStart, (int) end));
                        members.add(row);
                    }
                    return null;
                }
            }.scan(unit, null);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("file", file);
            row.put("class", cls);
            row.put("method", method);
            row.put("members", members);
            output.add(row);
        }
        json.writeValue(System.out, output);
    }
}
