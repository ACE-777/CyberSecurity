### Правило на Codeql
Данное правило определяет в классе ShellUtils потенциальную уязвимость:

```
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
```

Таким образом мы получаем, что у нас в обновленной версии alluxio на месте старого одиночного метода
`result=ShellUtils.execCommand(ShellUtils.getGroupsForUserCommand(user));`
находятся похожие по семантике методы:
![img.png](img.png)
Также посмотрев внутрь вызова можем обнаружить то самое возвращение массива string, где раньше было
`return new String[] {"bash", "-c", "id -gn " + user + "; id -Gn " + user};`
![img_1.png](img_1.png)

Таким образом в предыдущей версии мы могли обратить внимание на то, что возможно исполнение скриптов,
которые мы можем передать в качестве `user`.

#### Исполнение
Для исполнения скачать кодовую базу с https://github.com/Alluxio/alluxio и исполнить codeql/example.ql 

### Правило на Semgrep
Следующее правило представлено для semgrep:
```
rules:
  - id: find-execCommand-with-getGroupsForUserCommand-argument
    patterns:
      - pattern-inside: |
          $X.execCommand($Y.$METHOD(... ,$Z, ...))
      - focus-metavariable: $Z
    message: "Found call to execCommand with getGroupsForUserCommand as argument"
    severity: WARNING
    languages:
      - java
```

Данное правило показывает нахождения трех функций, удовлетворяющему нашему правилу.
![img_2.png](img_2.png)

Если поизучать в коде внутри `306┆ result = ShellUtils.execCommand(ShellUtils.getGroupsForUserCommand(user));`, то можно
обнаружить исполнение команды, в которую мы можем передать скрипт. Таким образом можно определить уязвимость.

#### Исполнение
Для исполнения можно clone https://github.com/ACE-777/alluxio и в корне исполнить 
```bash
semgrep scan --config rule.yaml
```

### Правило на Joern
Порядок команд для dataflow анализа в joern:
```bash
val src = cpg.typeDecl.isPublic.method.isPublic.parameter
val sink = cpg.call.name("execCommand").argument
sink.reachableByFlows(src)
```
![img_3.png](img_3.png)

#### Исполнение
Установить joern
Затем:
```bash
./joern
importCode("/home/mishadyagilev/GolandProjects/alluxio","alluxio","JAVASRC")
val src = cpg.typeDecl.isPublic.method.isPublic.parameter
val sink = cpg.call.name("execCommand").argument
sink.reachableByFlows(src)
```