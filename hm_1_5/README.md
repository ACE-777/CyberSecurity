## Запуск дебага
Из корня репы перейти:
```bash
cd hm_1_5/demo2
```
Собрать pom-ник:
```bash
mvn clean install
```

## Правило на codeql
```bash
import java


class RuntimeExec extends Method {
  RuntimeExec(){
    hasQualifiedName("java.lang", "Runtime", "exec")
  }
}

from MethodCall ma
where ma.getMethod() instanceof RuntimeExec
select ma.getEnclosingStmt()
```

Соответсвующее правило детектирует потенциальную уязвимость в методе `alluxio.util.io.FileUtils.setLocalDirStickyBit` библиотеки alluxio всех версий
до настоящей (2.9.3). Более того, данная библиотека совместима только с Java 8.
```
  public static final String SEPARATOR = "/";

  public static void setLocalDirStickyBit(String dir) {
    try {
      // Support for sticky bit is platform specific. Check if the path starts with "/" and if so,
      // assume that the host supports the chmod command.
      if (dir.startsWith(AlluxioURI.SEPARATOR)) {
        // TODO(peis): This is very slow. Consider removing this.
        Runtime.getRuntime().exec("chmod +t " + dir);
      }
    } catch (IOException e) {
      LOG.info("Can not set the sticky bit of the directory: {}", dir, e);
    }
  }
```

## Результаты экспериментов
Был проведен класс экспериментов нацеленных на выявление исполнения какой-либо команды после защиты каталога с файлами. 
```
String dir1 = "/path/to/directory | echo 123/";
String dir1 = "/ bad; rm /home/mishadyagilev/javaFolder/demo2/fine/one.txt";
String dir1 = "/cd | bash rm fine/one.txt";
String dir1 = "/cd | bash rm /home/mishadyagilev/javaFolder/demo2/fine/one.txt";
String dir1 = "/bash rm /home/mishadyagilev/javaFolder/demo2/fine/one.txt";
String dir1 = "/cd | rm /fine/one.txt";
String dir1 = "/cd | #!/bin/bash -ex rm -rf fine/one.txt";
String dir1 = "/cd | #!/bin/bash -ex rm -rf fine/one.txt";
String dir1 = "/cd | bash -c rm fine/one.txt";
String dir1 = "/bad | bash -c rm fine/one.txt";
String dir1 = "/bad; cd ./fine; rm one.txt\"";
String dir1 = "/ bash echo \"bad; cd ./fine; rm one.txt\"";
String dir1 = "/fine +\"; cd ./fine; rm one.txt\"";
String dir1 = "/fine;\" cd ./fine; rm one.txt\"";
String dir1 = "/fine; ";
String dir1 = "/bad; cd ./fine && rm one.txt";
String dir1 = "/bad; rm -f ./fine/one.txt";
String dir1 = "/; rm ./home/mishadyagilev/javaFolder/demo2/fine/one.txt";
String dir1 = "/; rm ./fine/one.txt";
String dir1 = "/home/mishadyagilev/javaFolder/demo2/four";
String dir1 = "/home/mishadyagilev/javaFolder/demo2/six | rm -f ./six/one.txt";
String dir1 = "/home/mishadyagilev/javaFolder/demo2/six | touch /home/mishadyagilev/javaFolder/demo2/six/two.txt";
String dir1 = "/ && rm -r /home/mishadyagilev/javaFolder/demo2/eight"; // work!
String dir1 = "/ && rm -r /home/mishadyagilev/javaFolder/demo2/ten/";
String dir1 = "/ && sudo rm one.txt";
String dir1 = "/ && sudo cd /home/mishadyagilev/javaFolder/demo2/fourteen | sudo rm *";
String dir1 = "/ && sudo touch one.txt";
String dir1 = "/home/mishadyagilev/javaFolder/demo2/top && rm -r /home/mishadyagilev/javaFolder/demo2/fifteen";
String dir1 = "/\"/\" && touch /home/mishadyagilev/javaFolder/demo2/three.txt";
String dir1 = "bash rm /home/mishadyagilev/javaFolder/demo2/fine/one.txt";
String dir1 = "/bin/sh, \"-c\", \"/usr/bin/gnome-calculator\"";
String dir1 = "/bin/sh -c /usr/bin/gnome-calculator";
String dir1 = "/new String[] {\"/bin/sh\", \"-c\",  \"/usr/bin/gnome-calculator\"}";
String dir1 = "/new String[] {\"/bin/sh\", \"-c\",  \"/usr/bin/gnome-calculator\"}";
String dir1 = "/ -c /usr/bin/gnome-calculator";
String[] dir2 = {"/","/bin/sh","-c","/usr/bin/gnome-calculator"};
String dir1 =  dir2.toString();
String dir1 = "/ sh -c pwd; /usr/bin/gnome-calculator";
String dir1 = "/ sh -c pwd; /usr/bin/gnome-calculator";

FileUtils.setLocalDirStickyBit(dir1.toString());
```
Однако ни одна из попыток не увенчалась успехом. По моему мнению, данная потенциальная уязвимость не является ей так как
дело в том, что Runtime.exec в Java позволяет запускать новую программу/процесс. Однако Runtime.exec пытается разбить
строку на массив слов, а затем выполняет первое слово в массиве с остальными словами в качестве параметров. Runtime.exec
ни в коем случае не пытается вызвать оболочку bash.
Именно поэтому `chmod` в `exec("chmod +t " + dir)` не позволяет с самого начала даже "включить" режим bash. А также
выполняется конкатенация строки, а не элементов массива. Таким образом даже фильтр на сепаратор не является центральной 
причиной неуязвимости по моему мнению.

То есть подкапотная часть стандартной функции выглядит следующим образом
```
public Process exec(String[] cmdarray) throws IOException {
      return this.exec((String[])cmdarray, (String[])null, (File)null);
   }
```

Более того я не нашел способа стирания команды в исполнении exec. То есть если была бы возможность стереть chmod и 
заменить его на массив из элементов "bash", "-c" или на "/bin/sh","-c", или на "/bin/bash","-c", то скорее всего можно 
было бы получить реально рабочую уязвимость.

В данном случае была бы рабочая уязвимость в следующем виде (как это есть например в моей первой домашке):
```
String[] dir4 = {"/bin/bash","-c","chmod +t /home/mishadyagilev/javaFolder/demo2/top | /usr/bin/gnome-calculator"};
Runtime.getRuntime().exec(dir4);
```

