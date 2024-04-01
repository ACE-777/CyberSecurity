/**
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class PublicMethodParameter extends DataFlow::Node{
    PublicMethodParameter(){
        exists(Method m, Parameter p|
            m.getDeclaringType().isPublic() and
            m.isPublic() and
            p = m.getAParameter() and
            p.getType().hasName("String") and
            this.asParameter() = p
            )
    }
}

class ScriptEcho extends DataFlow::Node {
    ScriptEcho() {
        exists(MethodCall ma|
            ma.getCallee().hasName("execCommand") and
            // ma.getCallee().getDeclaringType().getASupertype*().hasQualifiedName("ShellUtils", "String") and
            this.asExpr() = ma.getArgument(0)
            )
    }
}

module MyFlowConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
        source instanceof PublicMethodParameter
    }

    predicate isSink(DataFlow::Node sink) {
        sink instanceof ScriptEcho
    }
}

module MyFlow = TaintTracking::Global<MyFlowConfig>;
import MyFlow::PathGraph

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
    "Source: " + source.getNode().asParameter().getCallable().getDeclaringType() + "." + source.getNode().asParameter().getCallable()
