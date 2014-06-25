package edu.upenn.kpass;

/*
 * This code originally from
 *    http://www.javaactivedirectory.com/?page_id=222
 * 
 * Adapted for java-kpass at Penn by
 *    Jorj Bauer <jorj@isc.upenn.edu>
 *    6/24/2014
 */

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;


public class ServiceTicketDecoder implements PrivilegedExceptionAction<String>
{
    protected byte[] serviceTicket;
    private String servicePrincipalName;

    private static final Oid kerberos5Oid;
    private static final Oid kerberosPrincipalNameOid;

    static {
        try {
            kerberos5Oid = new Oid("1.2.840.113554.1.2.2");
            kerberosPrincipalNameOid = new Oid("1.2.840.113554.1.2.2.1");
        } catch (GSSException ex) {
            throw new Error(ex);
        }
    }

    public ServiceTicketDecoder(String servicePrincipalName, byte[] serviceTicket)
    {
	// the run() method does not support any arguments, so we pass the service ticket in via the constructor
	this.serviceTicket = serviceTicket;
	this.servicePrincipalName = servicePrincipalName;
    }

    public String run() throws PrivilegedActionException
    {
	try
	    {
		// create a GSSManager, which will do the work
		GSSManager gssManager = GSSManager.getInstance();

		GSSName serviceName = gssManager.createName(servicePrincipalName,
							    kerberosPrincipalNameOid);

		// get the service's credentials. note that this run() method was called by Subject.doAs(),
		// so the service's credentials (Service Principal Name and password) are already available in the Subject
		GSSCredential serviceCredentials = gssManager.createCredential(serviceName,
									       GSSCredential.INDEFINITE_LIFETIME,
									       kerberos5Oid,
									       GSSCredential.ACCEPT_ONLY);

		// create a security context for decrypting the service ticket
		GSSContext gssContext = gssManager.createContext(serviceCredentials);

		// decrypt the service ticket
		gssContext.acceptSecContext(this.serviceTicket, 0, this.serviceTicket.length);

		// get the client name from the decrypted service ticket
		// note that Active Directory created the service ticket, so we can trust it
		String clientName = gssContext.getSrcName().toString();

		// clean up the context
		gssContext.dispose();

		// return the authenticated client name
		return clientName;
	    }
	catch (Exception ex) {
	    throw new PrivilegedActionException(ex);
	}
    }
}
