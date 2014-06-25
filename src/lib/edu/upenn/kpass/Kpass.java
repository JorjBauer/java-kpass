package edu.upenn.kpass;

import java.io.File;
import java.io.Console;
import java.util.Map;
import java.util.Iterator;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.AppConfigurationEntry;

import java.util.Set;
import javax.security.auth.Subject;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;

public class Kpass {

    /**
     * Determine the service principal in the jaas.conf file, so it doesn't 
     * have to be hard-coded in multiple locations.
     */
    private static String getServicePrincipal()
    {
	Configuration c = Configuration.getConfiguration();
	AppConfigurationEntry[] a = c.getAppConfigurationEntry("Server");

        for (AppConfigurationEntry entry: a) {
	    if ("com.sun.security.auth.module.Krb5LoginModule".equals(entry.getLoginModuleName())) {
		Object principal = entry.getOptions().get("principal");
		return principal.toString();
	    }
	}
	throw new RuntimeException("Can't determine 'principal' from Server section of jaas configuration file");
    }

    /**
     * Validate a username/password via Kerberos
     * @param username
     * @param password
     * @return true for ok; false if not
     */
    public static boolean validate(String username, String password) 
	throws PrivilegedActionException
    {
	/* Extract the service_principal name from jaas.conf */
	String service_principal = getServicePrincipal();

	/* Construct a client login context in which we can kinit */

	try {
	    LoginContext lc = new LoginContext("Client", 
					       new UsernamePasswordHandler(username,
									   password));

	    /* Log it in, which will populate the ticket cache */

	    lc.login();

	    /* Extract the principal and use it to retrieve a service principal ticket */
	    
	    Subject subject = lc.getSubject();
	    Set<Principal> principalSet = subject.getPrincipals();
	    if (principalSet.size() != 1)
		throw new AssertionError("Expected only one principal: " + principalSet);
	    Principal userPrincipal = principalSet.iterator().next();
	    
	    PrivilegedAction<byte[]> action = new KinitAction(userPrincipal.getName(),
							      service_principal,
							      30 /* seconds */
							      );
	    
	    byte[] resp = (byte[])Subject.doAs( lc.getSubject(), action );
	    
	    /* Construct a server instance, used to validate that the TGS is valid.
	     * Note that this requires access to a service principal; the location 
	     * of the keytab and the name of the service principal must be embedded 
	     * in jaas.conf (in the "Server" section).
	     */
	    
	    LoginContext server_context = new LoginContext("Server");
	    
	    /* Populate the server's cache from its keytab file via login() */

	    server_context.login();
		
	    /* Validate the ticket via ServiceTicketDecoder, which will return 
	     * the name of the principal used for AuthN */
		
	    Subject serviceSubject = server_context.getSubject();
	    ServiceTicketDecoder decoder = new ServiceTicketDecoder(service_principal,
								    resp);
	    String clientName = (String) Subject.doAs(serviceSubject, decoder);

	    System.out.println("Client principal: " + clientName);

	    /* Destroy the ticket caches */
	    lc.logout();
	    server_context.logout();
	    
	    return true;
	} catch (LoginException e) {
	    e.printStackTrace();
	}
	return false;
    }
}
