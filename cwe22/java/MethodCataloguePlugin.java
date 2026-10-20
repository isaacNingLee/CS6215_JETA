package cs6215;

import com.fasterxml.jackson.databind.ObjectMapper;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.ir.exp.InvokeInstanceExp;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.classes.JMethod;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/** Exports program facts after pointer analysis; no taint policy is required. */
public class MethodCataloguePlugin implements Plugin {
    private Solver solver;

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
    }

    private static Map<String, Object> variable(Var var) {
        if (var == null) return null;
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("index", var.getIndex());
        row.put("name", var.getName());
        row.put("type", var.getType().toString());
        return row;
    }

    @Override
    public void onFinish() {
        try {
            Set<String> projectClasses = new HashSet<>(Files.readAllLines(
                    Path.of(System.getProperty("catalogue.projectClasses"))));
            var graph = solver.getResult().getCallGraph();
            var reachable = graph.reachableMethods()
                    .sorted(Comparator.comparing(JMethod::getSignature)).toList();
            Map<String, Map<String, Object>> methods = new TreeMap<>();
            List<Map<String, Object>> calls = new ArrayList<>();
            List<Map<String, Object>> skipped = new ArrayList<>();

            for (var method : reachable) {
                if (!projectClasses.contains(method.getDeclaringClass().getName())) continue;
                var row = describe(method, projectClasses, graph.contains(method));
                methods.put(method.getSignature(), row);
                if (method.isAbstract() || method.isNative()) continue;
                var ir = method.getIR();
                row.put("parameters", ir.getParams().stream()
                        .map(MethodCataloguePlugin::variable).toList());
                row.put("receiver", variable(ir.getThis()));
                List<Map<String, Object>> statements = new ArrayList<>();
                for (var stmt : ir) {
                    Map<String, Object> statement = new LinkedHashMap<>();
                    statement.put("index", stmt.getIndex());
                    statement.put("line", stmt.getLineNumber());
                    statement.put("kind", stmt.getClass().getSimpleName());
                    statement.put("text", stmt.toString());
                    statements.add(statement);
                    if (!(stmt instanceof Invoke call)) continue;
                    String id = method.getSignature() + "#" + stmt.getIndex();
                    if (call.isDynamic()) {
                        skipped.add(Map.of("id", id, "reason", "invokedynamic is not modelled by this catalogue"));
                        continue;
                    }
                    Map<String, Object> site = new LinkedHashMap<>();
                    site.put("id", id);
                    site.put("caller", method.getSignature());
                    site.put("statement_index", stmt.getIndex());
                    site.put("line", stmt.getLineNumber());
                    site.put("declared_target", call.getMethodRef().toString());
                    var resolved = call.getMethodRef().resolveNullable();
                    site.put("resolved_target", resolved == null ? null : resolved.getSignature());
                    if (resolved != null) methods.putIfAbsent(resolved.getSignature(),
                            describe(resolved, projectClasses, graph.contains(resolved)));
                    var targets = graph.getCalleesOf(call).stream()
                            .sorted(Comparator.comparing(JMethod::getSignature)).toList();
                    site.put("possible_targets", targets.stream().map(JMethod::getSignature).toList());
                    for (var target : targets) methods.putIfAbsent(target.getSignature(),
                            describe(target, projectClasses, graph.contains(target)));
                    var expression = call.getInvokeExp();
                    site.put("arguments", expression.getArgs().stream()
                            .map(MethodCataloguePlugin::variable).toList());
                    site.put("receiver", expression instanceof InvokeInstanceExp instance
                            ? variable(instance.getBase()) : null);
                    site.put("result", variable(call.getResult()));
                    site.put("invocation_kind", call.isStatic() ? "static" : call.isSpecial()
                            ? "special" : call.isInterface() ? "interface" : "virtual");
                    calls.add(site);
                }
                row.put("statements", statements);
            }
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("schema_version", 1);
            output.put("scope", "Reachable project/adapter methods and their direct API targets; "
                    + "library bodies and unreachable project methods are excluded.");
            output.put("entry_methods", graph.entryMethods().map(JMethod::getSignature).sorted().toList());
            output.put("reachable_method_count_including_libraries", reachable.size());
            output.put("methods", new ArrayList<>(methods.values()));
            output.put("call_sites", calls);
            output.put("skipped_calls", skipped);
            new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(
                    Path.of(System.getProperty("catalogue.output")).toFile(), output);
        } catch (Exception e) {
            throw new IllegalStateException("Catalogue export failed", e);
        }
    }

    private static Map<String, Object> describe(JMethod method, Set<String> classes, boolean reachable) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("signature", method.getSignature());
        row.put("declaring_class", method.getDeclaringClass().getName());
        row.put("name", method.getName());
        row.put("parameter_types", method.getParamTypes().stream().map(Object::toString).toList());
        row.put("return_type", method.getReturnType().toString());
        row.put("static", method.isStatic());
        row.put("constructor", method.isConstructor());
        row.put("native", method.isNative());
        row.put("abstract", method.isAbstract());
        row.put("phantom_class", method.getDeclaringClass().isPhantom());
        row.put("project_class", classes.contains(method.getDeclaringClass().getName()));
        row.put("reachable", reachable);
        return row;
    }
}
