# POUND - REVERSE-PROXY AND LOAD-BALANCER

    The Pound program is a reverse proxy, load balancer and
    HTTPS front-end for Web server(s). Pound was developed
    to enable distributing the load among several Web-servers
    and to allow for a convenient SSL wrapper for those Web
    servers that do not offer it natively. Pound is distributed
    under the GPL - no warranty, it's free to use, copy and
    give away.


## IMPROVEMENTS

	ZEVENET Dev team has added and imported some properties to
	Pound Reverse-Proxy in order to offer some new
	functionalities required for critical environments.
	They can be checked in the git commits but the
	following lines describe the most important changes:

	1. Added support for HSTS headers
	commit: 802f41a26c29176bf371be1b5f379a435b044648
	2. Supported 100Continue headers
	commit: dcbbff5b7514c267b8a9caa5c336479a99cce8d4
	3. Added new Directive Name in order to log with
	a higher level of detail
	commit: ca007c53944377618f1d07eb93d1cb90f3eafd05
	4. Poundctl counts backend established conns.
	commit: 8044ed9daa966b89e031a8da05bbdf3041b33a93
	5. Supported Openssl 1.0.2 Compilation
	commit: 8044ed9daa966b89e031a8da05bbdf3041b33a93
	6. Supported Openssl 1.1 Compilation
	commit: 68b2a5a958536d04be4560806ec19f80c6e292f1
	7. Supported loadbalancing with websockets
	commit: 9d608feb9bca29d9d9b319a7ec35fe9eda1f15ed
	8. Compatibility with Web Application Firewall (WAF) using Libmodsecurity
	commit: 42600bbdaf088fddc0adf604f456c4857ea68a4a


## WHAT POUND IS:

    1.  a reverse-proxy: it passes requests from client
        browsers to one or more back-end servers.

    2.  a load balancer: it will distribute the requests from
        the client browsers among several back-end servers,
        while keeping session information.

    3.  an SSL wrapper: Pound will decrypt HTTPS requests
        from client browsers and pass them as plain HTTP
        to the back-end servers.

    4.  an HTTP/HTTPS sanitizer: Pound will verify requests
        for correctness and accept only well-formed ones.

    5.  a fail over-server: should a back-end server fail,
        Pound will take note of the fact and stop passing
        requests to it until it recovers.

    6.  a request redirector: requests may be distributed
        among servers according to the requested URL.

    Pound is a very small program, easily audited for security
    problems. It can run as setuid/setgid and/or in a chroot
    jail. Pound does not access the hard-disk at all (except
    for reading certificate file(s) on start, if required)
    and should thus pose no security threat to any machine.


## WHAT POUND IS NOT:

    1.  Pound is not a Web server: by itself, Pound serves no
        content - it contacts the back-end server(s) for that
        purpose.

    2.  Pound is not a Web accelerator: no caching is done -
        every request is passed "as is" to a back-end server.


## STATUS

    As of release 1.0 Pound is declared to be production-quality code.

    Quite a few people have reported using Pound successfully in production
    environments. The largest volume reported to date is a site with an
    average of about 30M requests per day, peaking at over 600 requests/sec.

    Pound was successfully used in production with a variety of Web servers,
    including Apache, IIS, Zope, WebLogic, Jakarta/Tomcat, iPlanet, etc. In
    general Pound passes requests and responses back and forth unchanged,
    so we have no reason to think that any web server would be incompatible.

    Client browsers that were tested:

    - IE 5.0/5.5 (Windows) HTTP/HTTPS

    - Netscape 4.7 (Windows/Linux) HTTP/HTTPS

    - Mozilla (Windows/Linux) HTTP/HTTPS

    - Konqueror (Linux) HTTP/HTTPS

    - Galleon (Linux) HTTP/HTTPS

    - Opera (Linux/Windows) HTTP/HTTPS

    - Lynx (Linux) HTTP

    Given that Pound is in production and no problems were reported, we have
    no reason to believe that other browsers would present a problem. A few
    issues were observed with problematic SSL implementations, most notably
    with Opera 6, but these should be OK in the present version.


# INSTALLATION

    Probably the easiest way to install Pound is to use a pre-compiled package
    if you can find one. While Apsis offers no such packages, they are available
    for quite a few systems (Suse, Debian and derivatives such as Ubuntu), as
    well as some private packages:

    - RPMs for RedHat are available at http://www.invoca.ch/pub/packages/pound/

    - A nice FreeBSD live-CD distribution is available at http://www.targeted.org as
    http://www.targeted.org/files/fbsd62_pound23.iso.gz, including a Pound binary.

    Failing that you should install from sources:

    1.  Pound was tested on Linux, Solaris and OpenBSD, but
        it should work unchanged on just about any modern
        Unix-like system. You will require at least OpenSSL and
        libpthread. The PCRE package is strongly recommended.

        Warning: as Pound is a multi-threaded program it requires
        a version of OpenSSL with thread support. This is normally
        the case on Linux and Solaris (for example) but not on *BSD.
        If your system has the wrong library please download, compile
        and install OpenSSL (from http://www.openssl.org).

        If the PCRE package is available Pound will link against it.
        This will provide a significant performance boost.

    2.  Download the current version of Pound-current file and unpack
        it. The archive is signed.
        My signature is available at http://www.apsis.ch/pound/roseg.asc.
        Alternately see below for stable versions.

        Unpack. Do the usual thing:

            ./configure

    3.  The following options are available for the configure script:

        --with-ssl=ssl_dir -- OpenSSL home directory (default: system defined).

        --disable-super -- disable supervisor process (default: enabled)

        --with-t_rsa=nnn   -- timeout of the RSA ephemeral keys regeneration
        (default: 1800 seconds).

        --with-owner=owner -- name of installed binaries owner (default is
        system-dependent).

        --with-group=group -- name of installed binaries group (default is
        system-dependent).

    4.  Check that the resulting Makefile is correct and possibly
        adjust flags as needed on your system. Compile:

            make

    5.  If it works, you may want to do some testing before installing.

    6.  Install the executable somewhere (it's likely that
        /usr/local/sbin would make a good choice), as well
        as the manual page (pound.8 -> /usr/local/man/man8).
        The supplied Makefile will do it for you.

    7.  Make sure Pound gets started on boot. Read the man
        page for available options and examples.



# CONFIGURATION

## ZOPE

    A special note for Zope users: the original intent on
    developing Pound was to allow distributing the load
    among several Zope servers running on top of ZEO. This
    it does.

    A special problem arises when you try using Pound as an
    SSL wrapper: Zope assumes that the requests are made via
    HTTP and insists on prepending 'http://' to the (correct)
    address in the replies, including in the <base> tag and
    the absolute URLs it generates (for images for example).
    This is clearly an undesirable behavior.

    For older Zope versions (prior to 2.7): a modified z2.py (as
    well as a patch) is included in the distribution. The main
    difference is that this z2.py allows starting an additional
    HTTP server via the -y flag that sets the environment
    HTTPS variable - thus correcting the problem. That means
    that in order to use Pound as an SSL wrapper you need to:

    - start Zope (modify the 'start' file) as:

        python -X -w 8080 -y 8443 ...

    For Zope 2.7 or later the same effect can be achieved via suitable
    modifications to zope.conf.



## VIRTUAL HOSTS (IN GENERAL)

    Some people asked about the possibility of redirecting requests to back-ends
    as per some virtual hosts definition. While I believe this is not Pound's
    job, it can be done. As of version 0.10, Pound supports filtering requests
    based not only on the request URL, but also on the presence or absence of
    certain headers.

    Let's assume that you have internal server 192.168.0.10 that is supposed to
    serve the needs of virtual host www.server0.com and 192.168.0.11 that serves
    www.server1.com.  You want Pound to listen on address 1.2.3.4 and separate
    the requests to each host.  The config file would look something like this:

        ListenHTTP
            Address 1.2.3.4
            Port    80

            Service
                HeadRequire "Host: .*www.server0.com.*"

                BackEnd
                    Address 192.168.0.10
                    Port    80
                End
            End

            Service
                HeadRequire "Host: .*www.server1.com.*"

                BackEnd
                    Address 192.168.0.11
                    Port    80
                End
            End
        End

    (add whatever else is necessary) or, if you want even safer filtering:

        ListenHTTP
            Address 1.2.3.4
            Port    80

            Service
                HeadRequire "Host: .*www.server0.com.*"
                HeadDeny    "Host: .*www.server1.com.*"

                BackEnd
                    Address 192.168.0.10
                    Port    80
                End
            End

            Service
                HeadRequire "Host: .*www.server1.com.*"
                HeadDeny    "Host: .*www.server0.com.*"

                BackEnd
                    Address 192.168.0.11
                    Port    80
                End
            End
        End

    This is NOT recommended (I personally believe that virtual hosts should be
    implemented in the back-end servers - putting this in a proxy
    is a major security kludge) but it works.



## VIRTUAL HOSTS AND HTTPS

    Quite often we get inquiries about Pound's ability to do virtual hosting
    with HTTPS. In order to lay this matter to rest, let me say:

        HTTPS does not allow virtual hosting!

    This is not a limitation of Pound, but of HTTPS - no Web server or proxy
    are able to do it due to the nature of the beast.

    In order to see why this is the case we need to look at the way HTTPS works.
    Basically there are three stages in any HTTPS connection:

    1.  Connection negotiation - the client (your browser) and the server (Web
        server or proxy) negotiate the basic parameters: ciphers to use, session
        key, etc.

    2.  Connection authentication: at the very least the server presents the
        client with a certificate that says "I am server www.encrypted.com - and
        certificate.authority.org will verify that". The client may also present
        a certificate of its own at this stage.

    3.  Request/response cycle: normal HTTP is sent (through the encrypted
        channel) back and forth.

    The vital point to notice here is that connection authentication takes place
    BEFORE any request was issued.

    On the other hand, the way virtual hosting works is for the client to
    specify in the request to which server it would like to talk. This is
    accomplished via a Host header:

        GET /index.html HTTP/1.1
        Host: http://www.virthost.com

    Combining the two we get to an impasse: on connection setup the server will
    reply with the certificate for "www.realhost.com", but the request is really
    for "www.virthost.com" - and most browsers will scream blue murder (as well
    they should) if the two do not match.

    There is a new twist on this however: some of the newer browsers will accept
    so-called "wild-card certificates". This is a specially crafted certificate
    that is not issued to a host, but rather to a domain. The result is that
    on setting-up a new SSL connection, the server replies not with "I am
    www.encrypted.com", but with "I am *.encrypted.com". If the browser is
    capable of processing this type of certificate then the connection is
    set up and normal HTTPS (with www.encrypted.com or special.encrypted.com or
    even some.other.server.encrypted.com or whatever other name matches) proceeds
    as usual. Pound supports these certificates and you can use virtual hosts in
    the normal way.

    Update June 2010: starting with the 2.6 series, Pound has SNI support, if your
    OpenSSL version supports it. Basically you supply Pound with several certificates,
    one for each virtual host (wild card certificates - as described above - are
    allowed). On connecting the client signals to which server it wants to talk,
    and Pound searches among its certificates which would fit. Not all versions
    of OpenSSL and not all clients support this mode, but if available it allows
    for virtual hosts over HTTPS.

    An additional option is to use a semi-official TLS extension, the so called
    alternate subject name. If your version of OpenSSL supports it you may specify
    in one certificate several alternate server names. This requires support for a
    special TLS feature, and nor all clients accept it.



## VIRTUAL HOSTS IN ZOPE

    For reasons I can't quite grasp, it seems that a lot of Zope
    users are convinced that virtual hosts are only possible through
    the Apache/VHM combination and that it requires some kind of
    magic incantation at midnight in order to work (I won't even
    start on the virgin sacrifices).

    The simple fact is that VHM and the Apache VirtualHost directives
    (as well as various tricks through mod_rewrite and mod_proxy) are
    (almost) mutually exclusive: they perform exactly the same
    functions and, leaving aside the logging issues, are used
    independently of each other.  Let me repeat that: you may use the
    VHM without Apache - just click on the VHM mappings tab and add
    whatever virtual host you wish. From this moment on any request
    to that host will be mapped back and forth by Zope to the required
    URL. This works weather you access Zope directly or via any number
    of proxies on the way, Pound included.

    To test: add a new host name to your /etc/hosts file, making it an
    alias for localhost - something like::

        127.0.0.1 localhost www.testhost.mine

    Add a mapping in VHM from www.testhost.mine to some Zope folder
    (Examples is already there). Point your browser to http://localhost
    and you get the normal Zope start page; point it to
    http://www.testhost.mine and you'll see the Examples starting page.
    All requests are mapped correctly, and the URLs in the pages (such
    as base or absoluteURL) are translated correctly in the response.


## SESSIONS

    Pound has the ability to keep track of sessions between a client
    browser and a back-end server. Unfortunately, HTTP is defined as
    a stateless protocol, which complicates matters: many schemes have
    been invented to allow keeping track of sessions, none of which works
    perfectly. Even worse, sessions are critical in order to allow
    web-based applications to function correctly - it is vital that once
    a session is established all subsequent requests from the same browser
    be directed to the same back-end server.

    Six possible ways of detecting a session have been implemented in
    Pound (hopefully the most useful ones): by client address, by Basic
    authentication (user id/password), by URL parameter, by cookie, by
    HTTP parameter and by header value.

    - by client address: in this scheme Pound directs all requests from
      the same client IP address to the same back-end server. Put the
      lines

      Session
        Type    IP
        TTL     300
      End

      in the configuration file to achieve this effect. The value indicates
      what period of inactivity is allowed before the session is discarded.

    - by Basic Authentication: in this scheme Pound directs all requests from
      the same user (as identified in the Basic Authentication header) to the
      same back-end server. Put the lines

      Session
        Type    Basic
        TTL     300
      End

      in configuration file to achieve this effect. The value indicates what
      period of inactivity is allowed before the session is discarded.

      WARNING: given the constraints of the HTTP protocol it may very well be
      that the authenticated request will go to a different back-end server than
      the one originally requesting it. Make sure all your servers support
      the same authentication scheme!

    - by URL parameter: quite often session information is passed through URL
      parameters (the browser is pointed to something like http://xxx?id=123).
      Put the lines

      Session
        Type    URL
        ID      "id"
        TTL     300
      End

      to support this scheme and the sessions will be tracked based on the value
      of the "id" parameter.

    - by cookie value: applications that use this method pass a certain cookie
      back and forth. Add the lines

      Session
        Type    Cookie
        ID      "sess"
        TTL     300
      End

      to your configuration file - the sessions will be tracked by the value of
      the "sess" cookie.

    - by HTTP parameter value: applications that use this method pass an HTTP
      parameter (http://x.y/z;parameter) back and forth. Add the lines

      Session
        Type    PARM
        TTL     300
      End

      to your configuration file - the sessions will be tracked by the value of
      the parameter.

    - by header value: applications that use this method pass a certain header
      back and forth. Add the lines

      Session
        Type    Header
        ID      "X-sess"
        TTL     300
      End

      to your configuration file - the sessions will be tracked by the value of
      the "X-sess" header.

    Please note the following restrictions on session tracking:

    - session tracking is always associated with a certain Service. Thus each
      group may have other methods and parameters.

    - there is no default session: if you have not defined any sessions no
      session tracking will be done.

    - only one session definition is allowed per Service. If your application
      has alternative methods for sessions you will have to define a separate
      Service for each method.

    A note on cookie injection: some applications have no session-tracking mechanism at
    all but would still like to have the client always directed to the same back-end
    time after time. Some reverse proxies use a mechanism called "cookie injection" in
    order to achieve this: a cookie is added to the back-end responses and tracked by the
    reverse proxy.

    Pound was designed to be as transparent as possible, and this mechanism is not
    supported. If you really need this sort of persistent mapping use the client address
    session mechanism (Session Type IP), which achieves the same result without
    changing the contents in any way.


## REQUEST LOGGING

    As a general rule, Pound passes all headers as they arrive from the client
    browser to the back-end server(s). There are two exceptions to this rule:
    Pound may add information about the SSL client certificate (as described
    below), and it will add an X-Forwarded-For header. The general format is:

        X-Forwarded-for: client-IP-address

    The back-end server(s) may use this extra information in order to create
    their log-files with the real client address (otherwise all requests will
    appear to originate from Pound itself, which is rather useless).

    In addition, Pound logs requests and replies to the system log. This is
    controlled by the LogLevel configuration variable (0 - no logging,
    1 - normal log, 2 - full log, 3 - Apache combined log format, 4 - Apache
    combined log format without virtual host).

    By default the messages go to the LOG_DAEMON facility, but you can change
    this in the configuration file. If you don't want to, you can just do a:

        fgrep pound /var/log/messages

    to get all the messages generated by Pound.


## HTTPS CERTIFICATES

    If a client browser connects via HTTPS and if it presents a
    certificate and if HTTPSHeaders is set, Pound will obtain the
    certificate data and add the following HTTP headers to the
    request it makes to the server:

    - X-SSL-Subject: information about the certificate owner

    - X-SSL-Issuer: information about the certificate issuer (CA)

    - X-SSL-notBefore: begin validity date for the certificate

    - X-SSL-notAfter: end validity date for the certificate

    - X-SSL-serial: certificate serial number (in decimal)

    - X-SSL-cipher: the cipher currently in use

    - X-SSL-certificate: the full client certificate (multi-line)

    It is the application's responsibility to actually use these
    headers - Pound just passes this information without checking
    it in any way (except for signature and encryption correctness).

    Please note that this mechanism allows forgeries: a client may
    (maliciously) send these headers to Pound in order to masquerade
    as an SSL client with a specific certificate. If this is a problem
    for your application make sure to deny these requests. Add:

        HeadDeny "X-SSL-Subject:.*"
        HeadDeny "X-SSL-Issuer:.*"
        HeadDeny "X-SSL-notBefore:.*"
        HeadDeny "X-SSL-notAfter:.*"
        HeadDeny "X-SSL-serial:.*"
        HeadDeny "X-SSL-cipher:.*"

    within the Service(s).


## THREADS AND LIMITS

    A few people ran into problems when installing Pound because of the
    various threading models and how they interact with system-imposed
    limits. Please keep in mind the following requirements:

    - on most System V derived Unices (of which Linux up to 2.4 is one),
      a thread is a process. This means that when doing a 'ps' you will see
      as many processes with the name 'pound' as there are active threads.
      Each such process uses only two file descriptors, but the system needs
      to support the required number of processes, both in total and per
      user (possibly also per process group). In bash, this is 'ulimit -u',
      in csh this is 'limit maxproc'.

    - on BSD style systems all threads run in the same process space. Do
      a ps and you see a single 'pound' process. The process needs two
      file descriptors per active request (bash: 'ulimit -n', csh
      'limit maxfiles'/'limit openfiles').

    - on most systems the thread library comes with a built-in limit on the
      maximal number of concurrent threads allowed - on older systems it usually
      is 1024, on newer systems quite a bit higher. In very
      rare cases (very high load and long response times) you may run into
      this limitation - the symptom is log messages saying "can't create
      thread". Your only solution is to recompile the system threads library
      (and possibly the kernel itself) with a higher limit.

    Please note that your kernel needs to be configured to support the
    required resources - the above are just the shell commands.

## SIMILAR SYSTEMS

    Quite a few people asked "What is wrong with Apache/Squid/
    stunnel/your_favorite? Do we really need another proxy
    system?". The simple answer is that there is nothing wrong -
    they are all excellent systems that do their jobs very well.
    The reasoning behind Pound is however slightly different:

    - In my experience, a load-balancer may easily become a
      bottle-neck in itself. If you have a heavily loaded site,
      there are few things more depressing than seeing your
      "load-balancer" slow down the entire network. This means that
      the load-balancer should be kept as light-weight as possible.

    - Security: auditing a large system for security issues is a
      major undertaking for anybody (ask Bill Gates about it). This
      implies that in order to avoid introducing new vulnerabilities
      into a system (after all, your installation is only as secure
      as its weakest component) the proxy/load-balancer should be
      kept as small as possible.

    - Protection: I assume Pound will be the only component exposed
      to the Internet - your back-end servers will run in a protected
      network behind it. This means that Pound should filter requests
      and make sure only valid, correctly formed ones are passed to the
      back-end servers, thus protecting them from malicious clients.

    Taking these criteria into consideration, it is easy to see why
    the other systems mentioned above do not fit:

    - Apache (with mod_proxy and mod_backhand): great system, but very
      large. Imposes a significant load on the system, complex set-up
      procedure (and it is so easy to get it wrong: check how many Apache
      servers allow proxying from and to external hosts). While Apache
      has proven remarkably exploit free, I wouldn't wish to go into a
      security audit for the tens of thousands of lines of code involved,
      not to mention all the additional modules.

    - Squid: great caching proxy, but even should load-balancing
      features become available in the future, do you really need
      caching on the load-balancer? After all, Pound can easily run on a
      disk-less system, whereas with Squid you'd better prepare a high
      throughput RAID. Squid is still perfectly usable as a caching
      proxy between Pound and the actual Web server, should it lack
      its own cache (which Zope happily has).

    - stunnel: probably comes closest to my understanding of software
      design (does one job only and does it very well). However, it
      lacks the load balancing and HTTP filtering features that I
      considered necessary. Using stunnel in front of Pound (for HTTPS)
      would have made sense, except that integrating HTTPS into Pound
      proved to be so simple that it was not worth the trouble.

    - your favourite system: let me know how it looks in light of the
      above criteria - I am always interested in new ideas.


## DEDICATED SERVERS

    Some people asked about the possibility of dedicating specific
    back-end servers to some clients - in other words, if a request
    originates from a certain IP address or group of addresses then
    it should be sent to a specific group of back-end servers.

    Given the ease with which IP addresses can be forged I am personally
    doubtful of the utility of such a feature. Even should you think it
    desirable, it is probably best implemented via the packet filter,
    rather than a proxy server. Assuming that requests from x.com are
    to go to s1.local, requests from y.com to s2.local and everything
    else to s3.local and s4.local, here is how to do it:

    - make sure your firewall blocks requests to port 8080, 8081 and 8082

    - configure Pound as follows:

        ListenHTTP
            Address 127.0.0.1
            Port    8080

            Service
                BackEnd
                    Address s1.local
                    Port    80
                End
            End
        End

        ListenHTTP
            Address 127.0.0.1
            Port    8081

            Service
                BackEnd
                    Address s2.local
                    Port    80
                End
            End
        End

        ListenHTTP
            Address 127.0.0.1
            Port    8082

            Service
                BackEnd
                    Address s3.local
                    Port    80
                End
                BackEnd
                    Address s4.local
                    Port    80
                End
            End
        End

    - have your packet filter redirect requests to the right local ports
      based on the origin address. In OpenBSD pf syntax this would be
      something like:

        rdr on rl0 from x.com to myhost.com port 80 -> localhost port 8080
        rdr on rl0 from y.com to myhost.com port 80 -> localhost port 8081
        rdr on rl0 from any to myhost.com port 80 -> localhost port 8082

      or in Linux iptables::

        iptables -t nat -A PREROUTING -p tcp -s x.com --dport 80 -i eth0 \
            -j DNAT --to 127.0.0.1:8080
        iptables -t nat -A PREROUTING -p tcp -s y.com --dport 80 -i eth0 \
            -j DNAT --to 127.0.0.1:8081
        iptables -t nat -A PREROUTING -p tcp --dport 80 -i eth0 -j DNAT \
            --to 127.0.0.1:8082

    This would give you the desired effect and probably better
    performance than a purely proxy-based solution (though the
    performance improvement is debatable, at least on Linux).


## WebDAV

    As of version 1.0 Pound supports the full WebDAV command-set. In
    fact, it has been tested and is known to (almost) work with the
    Microsoft Outlook Web Gateway, which is quite remarkable given that
    Microsoft's own proxy does not.

    Regrettably, Microsoft adherence to standards leaves something to be
    desired: they decided to add some characters to their URLs - thus
    breaking a whole set of RFC's.

    Rather then change Pound to accept these characters (which could create
    some serious issues with security on other systems) we have made this
    behaviour dependent on a configuration switch: xHTTP (see the man page
    for details).

    If you also use the SSL wrapper feature in front of a Microsoft server
    you should probably also add 'AddHeader "Front-End-Https: on"'.

    These changes are also required to access a Subversion server via
    Pound.



## WEB APPLICATION FIREWALL, WAF

Libmodsecurity has been integrated with Pound, in order to analyze the
incoming traffic and defending the servers of possible HTTP attacks.
This feature allows configuring security policies and denying the service
for the non-desire requests.

Some protections rules are available in the [owasp-modsecurity-crs] (https://github.com/SpiderLabs/owasp-modsecurity-crs)
project

A benchmark analyze and comparison with Nginx  has been done with the following results:

Pound has been configured for inspecting the incoming traffic with Libmodsecurity
and forwarding it to the backend. The test was repeated for Nginx using Libmodsecurity,
the results are exposed here.

Host machine, load balancer:
CPU: Intel Xeon E3-1245 v5, 3.5GHz with 8 cores

The stress tool command: wrk -c 20 -d 20 -t 10 http://127.0.0.1/index.html

The red cells are showing the CPU is over the 90%
![Benchmark](benchmark_waf.png)

![Graph](graph_waf.png)

Pound and Nginx converge at the same point, they have the same bottleneck. Pound, being
more light, has a better performance when it is not overloaded.



## OTHER ISSUES

    The following problems were reported by various people who use pound:

    - delays in loading pages when the client browser is IE 5.5 (possibly
      limited to W2K/XP). It seems that IE opens exactly 4 connections (sockets)
      to the server and keeps them open until some time-out or until the server
      closes the connection. This works fine, unless you redirect IE to another
      server - given that all 4 sockets are used IE waits for a while before
      the redirect is actually performed.

      Solution: use the directive "Client 1" to ensure that Pound closes
      sockets very early, thus freeing the necessary resources. Experiment with
      the time-out - as it may cause problems with slow connections.

    - Pound fails to start; HTTPS is enabled and the message "can't read
      private key from file xxx" appears in the log.

      Solution: make sure that the certificate file includes:

      - (optional) a chain of certificates from a known certificate authority to
        your server certificate

      - the server certificate

      - the private key; the key may NOT be password-protected

      The file should be in PEM format. The OpenSSL command to generate a
      self-signed certificate in the correct format would be something like::

        openssl req -x509 -newkey rsa:1024 -keyout test.pem -out test.pem \
            -days 365 -nodes

      Note the '-nodes' flag - it's important!

    - Pound fails to operate correctly with SSL when RootJail is specified.
      Solution: OpenSSL requires access to /dev/urandom, so make sure such a
      device is accessible from the root jail directory. Thus if your root
      jail is something like /var/pound:

        mkdir /var/pound/dev
        mknod /var/pound/dev/urandom c 1 9

      or whatever major/minor number are appropriate for your system.

    - In chroot mode logging may stop functioning.
      Solution: make sure /dev and the root jail are on the same filesystem
      and create a hard link in the root jail to /dev/log:

        mkdir /chroot/jail/dev
        ln /dev/log /chroot/jail/dev/log

      Alternately you can have syslog (or syslog-ng) listen on another
      socket - see the man page for details.

    - In chroot mode name resolution (and especially redirects) may stop
      functioning.  Solution: make sure your resolver works correctly in the
      jail. You probably need copies of /etc/resolv.conf and (at least part)
      of /etc/hosts. Depending on your system additional files may be required
      check your resolver man page for details. Should name resolution fail the
      translation of host names to IP addresses would fail, thereby defeating
      the mechanism Pound uses to identify when should a Redirect be rewritten.

    - IE 5.x fails to work (correctly or at all) with Pound in HTTPS mode.
      Solution: define the supported OpenSSL ciphers for IE compatibility (this
      is really a work-around for a known IE bug):

      Ciphers "ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL"

      (Thanks to Andi Roedl for the tip).

    - Linux-specific: some people use various redundant Pound solutions for
      Linux which require Pound instances on separate machines to bind to the
      same address. The default configuration of Linux does not allow a
      program to bind() to non-local addresses, which may cause a problem.
      Solution: add

        echo 1 > /proc/sys/net/ipv4/ip_nonlocal_bind

      in your start-up script, or just set

        net.ipv4.ip_nonlocal_bind = 1

      in /etc/sysctl.conf (if you have one).

      (Thanks to RUne Saetre for the suggestion).


# PROJECT INFO

## COPYRIGHT

    Pound is copyrighted by Apsis GmbH and is distributed under
    the terms of the GNU Public License with the additional
    exemption that compiling, linking, and/or using OpenSSL is
    allowed. Basically, this means that you can use it free of
    charge, copy it, distribute it (provided the copyright is
    maintained and the full package is distributed), modify it,
    or line a bird-cage with it.

    We would be happy to hear from you if you use it and
    suggestions and improvements are gladly accepted.



## MAILING LIST

    Pound has its own mailing list now: please send a message with
    the subject "subscribe" to pound@apsis.ch in order to
    subscribe. You will receive confirmation and instructions in
    the reply.

    All messages are available and indexed (searcheable) in the
    archive http://www.apsis.ch/pound/pound_list.

    The mailing list is the primary support forum for Pound - please
    post there any questions you may have. The developpers' address is
    given here for information purposes only.



## ACKNOWLEDGMENTS

    Albert (of Alacra) for investigating and writing the TCP_NODELAY code.

    Luuk de Boer did some serious testing and debugging of the WebDAV
    code for Microsoft servers.

    Alession Cervellin packages and makes available Solaris packages for
    various Pound versions.

    David Couture found some nasty, lurking bugs, as well as contributing
    some serious testing on big hardware.

    Frank Denis contributed a few excellent code patches and some good ideas.

    Dmitriy Dvoinikov makes available a live-CD FreeBSD distribution that
    includes a Pound binary.

    Abner G. Jacobsen did a lot of testing in a production environment
    and contributed some very nice ideas.

    Akira Higuchi found a significant security issue in Pound and contributed
    the code to fix it.

    Ken Lalonde contributed very useful remarks and suggestions, as well as
    correcting a few code errors.

    Phil Lodwick contributed essential parts of the high-availability code and
    came up with some good ideas. In addition, did some serious testing under
    heavy loads.

    Simon Matter packages and makes available RPMs for various Pound versions.

    Jan-Piet Mens raised some interesting security points about the HTTPS
    implementation and brought the original idea for SSL header filtering.

    Andreas Roedl for testing and some ideas about logging in root jails.

    Gurkan Sengun tested Pound on Solaris, contributed the Solaris cc flags
    and makes a Solaris pre-compiled version available on his Web-site
    (www.linuks.mine.nu)

    Shinji Tanaka contributed a patch for controlling logging to disk files.
    This is available at http://www.hatena-inc.co.jp/~stanaka/pound/

    Jim Washington contributed the code for WebDAV and tested it.

    Maxime Yve discovered a nasty bug in the session tracking code and
    contributed the patch to fix it.

    All the others who tested Pound and told me about their results.


## [www.relianoid.com](https://www.relianoid.com)
