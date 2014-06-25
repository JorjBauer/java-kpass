Set it up something like this:

* create a service principal against which you can authenticate, and
  extract it to a keytab file

kadmin> addprinc -randkey +requires_preauth +allow_svr passwordcheck/host.name.example.com

kadmin> ktadd -k /tmp/service.keytab passwordcheck/host.name.example.com

* configure conf/krb5.conf and conf/jaas.conf (see the *.example
  files) so that jaas.conf is pointing to the correct keyTab file,
  using the same principal name you chose in the first step

Build using ant, which creates Kpass.jar in the lib/ directory:

	$ ant

Test using ant:

	$ ant test -Duser=<username> -Dpass=<password>
	...
	[exec] Authenticating user <username>
	[exec] Client principal: <username>@EXAMPLE.COM
	[exec] true

Or invoke it directly, which doesn't require a password on the command
line:

	$ ant compile-test
	$ java \
	  -Djava.security.krb5.conf=conf/krb5.conf \
	  -Djava.security.auth.login.config=conf/jaas.conf \
	   -classpath .:lib/Kpass.jar \
	   Ktest \    
	   <username>

	Authenticating user <username>
	[Password for <username>:]
	Client principal: <username>@EXAMPLE.COM
	true

Or write your own code to use the jar:

	import edu.upenn.kpass.Kpass;
	boolean passwordIsOkay = Kpass.validate(username, password);

Longer explanation...

It's common to see improper use of Kerberos for password
verification. The protocol's strength is that it never passes the
password over the wire. Its weakness is that it's complex, leading to
improper use. And, generally speaking, you should avoid trying to
validate Kerberos passwords directly; this undermines the purpose of a
security architecture that never requires passwords on the wire. But
sometimes it's unavoidable, and one has to live with this compromise.

Java doesn't make this any easier; its implementation is weak and
incomplete [1].

Here's a brief overview of how Kerberos works, and why the default
Java Krb5LoginModule is not sufficient to tell whether or not a
password is correct.

A client wants to use Kerberos. It constructs an AS_REQ ("kinit")
packet and encrypts it with the user's password. The AS_REQ is sent
(typically as a UDP packet) to the KDC. The server decrypts it, and in
doing so proves that the password is correct. It sends back a reply
essentially saying that it was successful, including the key that
the user requested.

That's where Java's Krb5LoginModule ends. That's where most first-try
implementations end. It feels, to the coder, like they're done. The
function returned a value, and if the password is wrong, then no key 
comes back.

Unfortunately, the reply is simple to spoof, both in terms of content
(a junk key reply in a "success!" wrapper) and delivery (being UDP,
it's easy to forge the origin). The first UDP packet that gets back to
the client wins, and if the client trusts the packet's say-so then
it's possible to brute-force your way in to kerberos-protected
applications that aren't completing the transaction. This is
particularly easy if you gain access to the client's subnet; it takes
essentially no time to send a pre-made packet, but takes a small
amount of time for the KDC to generate its response and put it on the
wire.

To be complete, the client must then also try to *use* the key 
that it got. Specifically, it must be used to get a service ticket, 
and then that service ticket has to be cryptographically validated 
using a service principal's private key.

This archive's code does its best given Java's limitations, and my
limited understanding of Java's security layers. I'm unable to find a
way to get Java to directly perform an AS_REQ for a service principal
(it demands krbtgt/REALM). So this code acts as both a Java client and
server - it performs a kinit, getting a TGT in the AS_REQ; and then
uses the TGT to send a TGS_REQ for a service key. Finally, it shuttles
that key off to a ServiceTicketDecoder object, which validates it
against a local keytab file. (This is identical to a typical Kerberos
client's workflow. It's just one more step than a server with a
service principal would normally have to perform to validate a
password.)

This may seem like a lot of heavy lifting for a simple thing. And it
is, because Java doesn't expose a function that performs
krb5_verify_init_creds() the way that C does. But this implementation
is at least correct (in terms of security and functionality) and is in
standard Sun Java (improving portability).

It also seems to be common practice to rely on setting the name of the
KDC directly. This is not good practice, because it disables
failover. This code relies on an external krb5.conf file to work
around this problem; the KDCs and the default REALM must be provided
there for this failover behavior to work properly. (There is probably
a more complex Configuration object setup that could be performed here
to populate the settings programmatically; I chose to not go down that
road due to complexity of the code that might be required.)

-- Jorj, 6/24/2014

[1] http://mail.openjdk.java.net/pipermail/security-dev/2011-March/002948.html

    Quote:

    [discussion about krb5_verify_init_creds() being missing] ... In other
    words, if this extra step is not performed inside the Krb5LoginModule
    then it is not secure for validating passwords.  Doing this extra step
    is standard in mod_auth_kerb, pam_krb5, etc.

    [reply from Weijun Wang at Oracle]
    We've always warned users that simply passing the Krb5LoginModule doesn't
    mean anything and you should always uses this subject in JGSS but not
    regarding itself as some kind of authenticity (say, use it in a java policy
    file).
