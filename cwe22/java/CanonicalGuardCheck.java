import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.lang.model.element.*;
import javax.tools.*;
import java.util.*;

/** Narrow, attributed guard checker. No project names, patch labels, or line numbers as rules.
 * Model: ordinary JDK File objects, trusted root parameter, no symlinks or filesystem races.
 * A rejection must precede a direct sink declaration in the SAME block, including a loop body.
 * Immutable aliases must come from local initializers; any assignment fails closed.
 */
public class CanonicalGuardCheck {
    static Trees trees;
    static CompilationUnitTree unit;
    static final Map<Element,VariableTree> declarations = new HashMap<>();
    static final Set<Element> assigned = new HashSet<>();
    static Set<Element> roots;
    static TreePath path(Tree t) { return TreePath.getPath(unit,t); }
    static Element symbol(Tree t) { return t == null ? null : trees.getElement(path(t)); }
    static long line(Tree t) { return unit.getLineMap().getLineNumber(trees.getSourcePositions().getStartPosition(unit,t)); }
    static ExpressionTree unwrap(ExpressionTree e) {
        while(e instanceof ParenthesizedTree p) e=p.getExpression();
        return e;
    }
    static boolean member(Tree t, String owner, String name) {
        Element e=symbol(t);
        return e != null && e.getSimpleName().contentEquals(name)
            && e.getEnclosingElement() instanceof TypeElement c && c.getQualifiedName().contentEquals(owner);
    }
    static Element local(ExpressionTree expression) {
        ExpressionTree e=unwrap(expression);
        if(!(e instanceof IdentifierTree)) return null;
        Element s=symbol(e);
        return s != null && !assigned.contains(s) &&
            (s.getKind()==ElementKind.LOCAL_VARIABLE || s.getKind()==ElementKind.PARAMETER) ? s : null;
    }
    static ExpressionTree initializer(Element s) {
        VariableTree v=declarations.get(s);
        return v == null ? null : v.getInitializer();
    }
    static Element canonicalFile(ExpressionTree expression, Set<Element> visited) {
        ExpressionTree e=unwrap(expression);
        Element s=local(e);
        if(s != null && visited.add(s)) {
            ExpressionTree init=initializer(s);
            return init == null ? null : canonicalFile(init,visited);
        }
        if(e instanceof MethodInvocationTree c && c.getArguments().isEmpty()
            && member(c,"java.io.File","getCanonicalPath") && c.getMethodSelect() instanceof MemberSelectTree sel)
            return local(sel.getExpression());
        return null;
    }
    static Element canonicalFile(ExpressionTree e) { return canonicalFile(e,new HashSet<>()); }
    static boolean rejects(StatementTree t) {
        if(t instanceof BlockTree b) return b.getStatements().size()==1 && rejects(b.getStatements().get(0));
        return t instanceof ThrowTree || t instanceof ReturnTree;
    }
    static boolean contains(IfTree guard, Element file, Element root) {
        if(guard.getElseStatement()!=null || !rejects(guard.getThenStatement())) return false;
        ExpressionTree condition=unwrap(guard.getCondition());
        if(!(condition instanceof UnaryTree u) || u.getKind()!=Tree.Kind.LOGICAL_COMPLEMENT) return false;
        ExpressionTree operand=unwrap(u.getExpression());
        if(!(operand instanceof MethodInvocationTree c) || !member(c,"java.lang.String","startsWith")
            || c.getArguments().size()!=1 || !(c.getMethodSelect() instanceof MemberSelectTree sel)
            || !file.equals(canonicalFile(sel.getExpression()))) return false;
        ExpressionTree arg=unwrap(c.getArguments().get(0));
        return arg instanceof BinaryTree b && b.getKind()==Tree.Kind.PLUS
            && root.equals(canonicalFile(b.getLeftOperand()))
            && member(unwrap(b.getRightOperand()),"java.io.File","separator");
    }
    static Map<String,Object> check(MethodTree method, NewClassTree sink) {
        Map<String,Object> row=new LinkedHashMap<>();
        Element m=symbol(method);
        row.put("class",m.getEnclosingElement().toString()); row.put("method",method.getName().toString());
        row.put("sink_line",line(sink)); row.put("protects_sink",false);
        row.put("reason","Unsupported canonical containment contract");
        if(sink.getArguments().size()!=1 || !symbol(sink).toString().equals("FileOutputStream(java.io.File)")) return row;
        Element file=local(sink.getArguments().get(0));
        if(file==null || roots.size()!=1) return row;
        ExpressionTree init=initializer(file);
        if(init==null || !(unwrap(init) instanceof NewClassTree f) || f.getClassBody()!=null
            || !member(f,"java.io.File","<init>") || f.getArguments().size()!=2
            || !symbol(f).toString().equals("File(java.io.File,java.lang.String)")) return row;
        Element root=local(f.getArguments().get(0));
        if(!roots.contains(root)) return row;
        // Sink must be the whole initializer of a direct statement, not conditional/lambda execution.
        TreePath sp=path(sink).getParentPath();
        if(!(sp.getLeaf() instanceof VariableTree v) || v.getInitializer()!=sink
            || !(sp.getParentPath().getLeaf() instanceof BlockTree block)) return row;
        // Reject declarations in local/anonymous classes and lambdas through the method scanner below.
        for(StatementTree statement:block.getStatements()) {
            if(statement==v) break;
            if(statement instanceof IfTree g && contains(g,file,root)) {
                row.put("protects_sink",true); row.put("guard_line",line(g));
                row.put("root_parameter",root.getSimpleName().toString());
                row.put("reason","Attributed JDK canonical paths + File.separator; rejecting guard dominates the same immutable File at a direct sink in the same block");
                return row;
            }
        }
        return row;
    }
    public static void main(String[] args) throws Exception {
        if(args.length<2) throw new IllegalArgumentException("classpath source.java ...");
        JavaCompiler compiler=ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> errors=new DiagnosticCollector<>();
        List<Object> output=new ArrayList<>();
        try(StandardJavaFileManager fm=compiler.getStandardFileManager(errors,null,null)) {
            JavacTask task=(JavacTask)compiler.getTask(null,fm,errors,List.of("-proc:none","-classpath",args[0]),null,
                fm.getJavaFileObjects(Arrays.copyOfRange(args,1,args.length)));
            List<CompilationUnitTree> units=new ArrayList<>(); task.parse().forEach(units::add);
            task.analyze(); trees=Trees.instance(task);
            if(errors.getDiagnostics().stream().anyMatch(d->d.getKind()==Diagnostic.Kind.ERROR))
                throw new IllegalArgumentException("Attribution failed: "+errors.getDiagnostics());
            for(CompilationUnitTree u:units) {
                unit=u;
                new TreeScanner<Void,Void>() {
                    public Void visitMethod(MethodTree m,Void ignored) {
                        if(m.getBody()==null) return null;
                        declarations.clear(); assigned.clear(); roots=new HashSet<>();
                        for(VariableTree p:m.getParameters()) if(symbol(p).asType().toString().equals("java.io.File")) roots.add(symbol(p));
                        List<NewClassTree> sinks=new ArrayList<>();
                        new TreeScanner<Void,Void>() {
                            public Void visitClass(ClassTree t,Void p) {return null;}
                            public Void visitLambdaExpression(LambdaExpressionTree t,Void p) {return null;}
                            public Void visitVariable(VariableTree v,Void p) {declarations.put(symbol(v),v);return super.visitVariable(v,p);}
                            public Void visitAssignment(AssignmentTree a,Void p) {assigned.add(symbol(a.getVariable()));return super.visitAssignment(a,p);}
                            public Void visitCompoundAssignment(CompoundAssignmentTree a,Void p) {assigned.add(symbol(a.getVariable()));return super.visitCompoundAssignment(a,p);}
                            public Void visitUnary(UnaryTree a,Void p) {
                                if(Set.of(Tree.Kind.PREFIX_INCREMENT,Tree.Kind.PREFIX_DECREMENT,Tree.Kind.POSTFIX_INCREMENT,Tree.Kind.POSTFIX_DECREMENT).contains(a.getKind())) assigned.add(symbol(a.getExpression()));
                                return super.visitUnary(a,p);
                            }
                            public Void visitNewClass(NewClassTree n,Void p) {
                                if(member(n,"java.io.FileOutputStream","<init>")) sinks.add(n);
                                return super.visitNewClass(n,p);
                            }
                        }.scan(m.getBody(),null);
                        for(NewClassTree s:sinks) output.add(check(m,s));
                        return null;
                    }
                }.scan(u,null);
            }
        }
        new ObjectMapper().writeValue(System.out,output);
    }
}
