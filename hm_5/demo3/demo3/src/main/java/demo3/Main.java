package demo3;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello world!");
//      String dir2 = "/usr/bin/gnome-calculator";
        String dir2 = "/bin/sh -c /usr/bin/gnome-calculator";
        ProcessPythonRunner.checkPythonEnvironment(dir2);
    }
}