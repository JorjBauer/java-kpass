import java.io.Console;

import edu.upenn.kpass.Kpass;

public class Ktest {

    public static void main(String[] args) {
	if (args.length != 2 && args.length != 1) {
	    String program = System.getProperty("sun.java.command").split(" ")[0];
	    System.err.println("Usage: " + program + " <username> [password]");
	    throw new RuntimeException("Args != 2 && Args != 1");
	}
	System.out.println("Authenticating user " + args[0]);

	String password = "";
	if (args.length == 2) {
	    password = args[1];
	} else {
	    Console cons;
	    char[] passwd;
	    if ((cons = System.console()) != null &&
		(passwd = cons.readPassword("[%s]", "Password for " + args[0] + ":")) != null) {
		password = String.valueOf(passwd);
	    } else {
		throw new RuntimeException("Couldn't read password");
	    }
	}

	try {
	    System.out.println(Kpass.validate(args[0], password));
	} catch (Exception ex) {
	    ex.printStackTrace();
	}
    }
}
