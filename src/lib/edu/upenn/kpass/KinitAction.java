package edu.upenn.kpass;

import java.security.PrivilegedAction;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class KinitAction implements PrivilegedAction<byte[]>
{
    /**
     * The user's principal, e.g. jorj@EXAMPLE.COM
     */
    private String userPrincipal;

    /**
     * The service which we will be testing against,
     * e.g. host/some.server@EXAMPLE.COM
     */
    private String servicePrincipal;

    /**
     * The lifetime requested for the service ticket, or 0 for
     * "DEFAULT"
     */
    private int lifetime;

    /**
     * Required glue in to the jgss AuthN layer
     */
    private static final Oid kerberos5Oid;
    private static final Oid kerberosPrincipalNameOid;

    static
    {
	try {
	    kerberos5Oid = new Oid("1.2.840.113554.1.2.2");
	    kerberosPrincipalNameOid = new Oid("1.2.840.113554.1.2.2.1");
        } catch (GSSException ex) {
            throw new Error(ex);
        }
    }


    public KinitAction(String userPrincipal, String servicePrincipal)
    {
	this(userPrincipal, servicePrincipal, 0);
    }


    public KinitAction(String userPrincipal, String servicePrincipal, int lifetime)
    {
	this.userPrincipal = userPrincipal;
	this.servicePrincipal = servicePrincipal;
	if (lifetime == 0) {
	    lifetime = GSSCredential.DEFAULT_LIFETIME;
	}
	this.lifetime = lifetime;
    }

    
    @Override
    public byte[] run()
    {
	try {
	    return createTicket();
	}
	catch (GSSException ex) {
	    throw new Error(ex);
	}
    }


    /**
     * Fetch a new service ticket for the constructor's service
     * principal, issued against the constructor's user principal, for
     * the constructor's lifetime.
     * @return the kerberos credential cache
     */
    public byte[] createTicket() throws GSSException
    {
	GSSManager manager = GSSManager.getInstance();

	/* Perform the initial AS_REQ (kinit) as the user */

	GSSName clientName = manager.createName(userPrincipal,
						kerberosPrincipalNameOid);

	GSSCredential clientCred = manager.createCredential(clientName,
							    lifetime,
							    kerberos5Oid,
							    GSSCredential.INITIATE_ONLY);

	/* Send a TGS_REQ for a service key that we can use */
	GSSName serviceName = manager.createName(servicePrincipal,
						 kerberosPrincipalNameOid);

	GSSContext context = manager.createContext(serviceName,
						   kerberos5Oid,
						   clientCred,
						   lifetime);

	byte[] response = (byte[]) context.initSecContext(new byte[0], 0, 0);

	context.dispose();

	return response;
    }
}
