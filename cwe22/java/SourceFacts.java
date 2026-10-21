import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.nio.file.*;
import java.util.*;

/** Parse only: exact source boundaries and a restricted structured AST, no execution. */
public class SourceFacts {
    static CompilationUnitTree unit;
    static SourcePositions positions;
    static String source;
    static Map<String,Object> node(Tree t) {
        Map<String,Object> n = new LinkedHashMap<>();
        if (t == null) return n;
        long start = positions.getStartPosition(unit,t), end = positions.getEndPosition(unit,t);
        n.put("kind",t.getKind().name());
        n.put("line",unit.getLineMap().getLineNumber(Math.max(0,start)));
        n.put("end_line",unit.getLineMap().getLineNumber(Math.max(0,end-1)));
        n.put("text",start>=0 && end>=start ? source.substring((int)start,(int)end) : t.toString());
        return n;
    }
    static Object expr(Tree t) {
        if (t == null) return null;
        if (t instanceof ParenthesizedTree x) return expr(x.getExpression());
        Map<String,Object> n=node(t);
        if(t instanceof IdentifierTree x) n.put("name",x.getName().toString());
        else if(t instanceof MemberSelectTree x) { n.put("base",expr(x.getExpression())); n.put("name",x.getIdentifier().toString()); }
        else if(t instanceof MethodInvocationTree x) {
            n.put("select",expr(x.getMethodSelect())); n.put("args",x.getArguments().stream().map(SourceFacts::expr).toList());
        } else if(t instanceof NewClassTree x) {
            n.put("type",x.getIdentifier().toString()); n.put("args",x.getArguments().stream().map(SourceFacts::expr).toList());
        } else if(t instanceof UnaryTree x) n.put("operand",expr(x.getExpression()));
        else if(t instanceof BinaryTree x) {n.put("left",expr(x.getLeftOperand()));n.put("right",expr(x.getRightOperand()));}
        else if(t instanceof AssignmentTree x) {n.put("target",expr(x.getVariable()));n.put("value",expr(x.getExpression()));}
        else if(t instanceof CompoundAssignmentTree x) {n.put("target",expr(x.getVariable()));n.put("value",expr(x.getExpression()));}
        return n;
    }
    static Object stmt(StatementTree t) {
        Map<String,Object> n=node(t);
        if(t instanceof BlockTree x) n.put("statements",x.getStatements().stream().map(SourceFacts::stmt).toList());
        else if(t instanceof VariableTree x) {
            n.put("name",x.getName().toString());n.put("type",x.getType().toString());n.put("value",expr(x.getInitializer()));
        } else if(t instanceof ExpressionStatementTree x) n.put("value",expr(x.getExpression()));
        else if(t instanceof IfTree x) {
            n.put("condition",expr(x.getCondition())); n.put("then",stmt(x.getThenStatement()));
            n.put("else",x.getElseStatement()==null?null:stmt(x.getElseStatement()));
        } else if(t instanceof ReturnTree x) n.put("value",expr(x.getExpression()));
        else if(t instanceof ThrowTree x) n.put("value",expr(x.getExpression()));
        return n;
    }
    public static void main(String[] args) throws Exception {
        JavaCompiler compiler=ToolProvider.getSystemJavaCompiler();
        List<Object> output=new ArrayList<>();
        for(String path:args) {
            source=Files.readString(Path.of(path));
            DiagnosticCollector<JavaFileObject> diagnostics=new DiagnosticCollector<>();
            try(StandardJavaFileManager fm=compiler.getStandardFileManager(diagnostics,null,null)) {
                JavacTask task=(JavacTask)compiler.getTask(null,fm,diagnostics,List.of("-proc:none"),null,
                        fm.getJavaFileObjects(path));
                unit=task.parse().iterator().next(); positions=Trees.instance(task).getSourcePositions();
                if(diagnostics.getDiagnostics().stream().anyMatch(d->d.getKind()==Diagnostic.Kind.ERROR))
                    throw new IllegalArgumentException("Java parse errors: "+path+" "+diagnostics.getDiagnostics());
                final String file=path;
                new TreeScanner<Void,Void>() {
                    final Deque<String> classes=new ArrayDeque<>();
                    public Void visitClass(ClassTree c,Void p) {
                        if(c.getSimpleName().length()==0) return null; // anonymous identities remain unresolved
                        classes.addLast(c.getSimpleName().toString()); super.visitClass(c,p);classes.removeLast();return null;
                    }
                    public Void visitMethod(MethodTree m,Void p) {
                        if(classes.isEmpty() || m.getBody()==null) return null;
                        Map<String,Object> row=node(m);
                        row.put("file",file); row.put("class_name",classes.getLast());
                        row.put("qualified_class",(unit.getPackageName()==null?"":unit.getPackageName()+".")+String.join("$",classes));
                        row.put("method_name",m.getName().contentEquals("<init>")?classes.getLast():m.getName().toString());
                        row.put("parameters",m.getParameters().stream().map(v->Map.of("name",v.getName().toString(),"type",v.getType().toString())).toList());
                        row.put("body",stmt(m.getBody()));
                        List<Object> guards=new ArrayList<>(), sinks=new ArrayList<>(), variables=new ArrayList<>(), writes=new ArrayList<>();
                        new TreeScanner<Void,Void>() {
                            public Void visitClass(ClassTree x,Void v){return null;}
                            public Void visitVariable(VariableTree x,Void v) {variables.add(stmt(x));return super.visitVariable(x,v);}
                            public Void visitAssignment(AssignmentTree x,Void v) {writes.add(expr(x));return super.visitAssignment(x,v);}
                            public Void visitCompoundAssignment(CompoundAssignmentTree x,Void v) {writes.add(expr(x));return super.visitCompoundAssignment(x,v);}
                            public Void visitIf(IfTree x,Void v) {
                                new TreeScanner<Void,Void>() {
                                    public Void visitMethodInvocation(MethodInvocationTree call,Void z) {
                                        if(call.getMethodSelect() instanceof MemberSelectTree sel && sel.getIdentifier().contentEquals("startsWith")) {
                                            Map<String,Object> g=node(call);g.put("call",expr(call));g.put("condition",expr(x.getCondition()));
                                            g.put("then",stmt(x.getThenStatement()));guards.add(g);
                                        }
                                        return super.visitMethodInvocation(call,z);
                                    }
                                }.scan(x.getCondition(),null);
                                return super.visitIf(x,v);
                            }
                            public Void visitNewClass(NewClassTree x,Void v) {
                                if(x.getIdentifier().toString().equals("FileOutputStream") || x.getIdentifier().toString().equals("java.io.FileOutputStream")) sinks.add(expr(x));
                                return super.visitNewClass(x,v);
                            }
                        }.scan(m.getBody(),null);
                        row.put("guards",guards);row.put("sinks",sinks);row.put("variables",variables);row.put("writes",writes);output.add(row);
                        return null;
                    }
                }.scan(unit,null);
            }
        }
        new ObjectMapper().writeValue(System.out,output);
    }
}
