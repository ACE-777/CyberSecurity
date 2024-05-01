package demo3;

import java.util.concurrent.TimeUnit;

public class ProcessPythonRunner {
    public static void checkPythonEnvironment(String cmd){
		try {
			Process process = Runtime.getRuntime().exec(cmd);
            if (process.waitFor(5,TimeUnit.SECONDS)){
				process.exitValue();
			}
		}
		catch (Exception e){
			e.printStackTrace();
		}
	}
}
