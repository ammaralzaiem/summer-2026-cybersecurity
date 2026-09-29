RECON WORKSHEET
================

Target:                 google.com
Date:                   4 September 2026
Authorization/source:   Public training target. Only passive lookups were used.
                        Nothing was scanned, logged into or attacked.

Tools used:             whois, dig, nslookup, curl, traceroute


1. WHOIS
---------
Registrar:              MarkMonitor, Inc.
Creation date:          15 September 1997
Expiration date:        14 September 2028
Nameservers:            ns1.google.com
                        ns2.google.com
                        ns3.google.com
                        ns4.google.com
Domain status:          clientDeleteProhibited
                        clientTransferProhibited
                        clientUpdateProhibited
                        serverDeleteProhibited
                        serverTransferProhibited
                        serverUpdateProhibited

                        These are locks. They stop the domain being moved,
                        changed or deleted unless the locks are lifted first.
                        All six are set, which is the safest setup.

DNSSEC:                 unsigned
Registrant:             Google LLC, United States
                        The contact email is hidden behind a web form.


2. DNS
-------
Resolver used:          192.168.1.1 (the local router)
                        The answers were marked non-authoritative, so they came
                        from a cache and not from Google's own nameservers.

A:                      142.251.39.206
AAAA:                   2a00:1450:4007:809::200e
NS:                     ns1.google.com, ns2.google.com,
                        ns3.google.com, ns4.google.com
MX:                     10 smtp.google.com

TXT:                    17 records in total.

                        SPF record:
                          v=spf1 include:_spf.google.com ~all

                        14 verification records. These are strings a company
                        adds to prove it owns the domain when signing up to an
                        outside service. The ones here name Google, Microsoft,
                        Facebook, Apple, DocuSign, OneTrust, Cisco, GlobalSign
                        and Arcules.

                        2 records with no obvious label.

DMARC:                  v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
                        (checked separately, it was not in the saved dig output)


3. HTTP
--------
Command used:           curl -I https://www.google.com

Status:                 HTTP/2 200
Server:                 gws (no version number given)
Content-Type:           text/html; charset=ISO-8859-1
Cache-Control:          private
HSTS:                   not present

Other security headers:
                        X-Frame-Options: SAMEORIGIN        present
                        X-XSS-Protection: 0                present
                        Content-Security-Policy            Report-Only
                        X-Content-Type-Options             missing
                        Referrer-Policy                    missing
                        Permissions-Policy                 missing

Also seen:
                        alt-svc: h3=":443", so HTTP/3 is supported
                        Two cookies were set (AEC and __Secure-ENID). Both have
                        Secure, HttpOnly and SameSite=lax.


4. NETWORK PATH
---------------
Traceroute tool:        traceroute on Linux
Approximate hops:       6
Notable hops:           1  100.64.5.91, which is carrier NAT
                        2  datapacket.com
                        3  cdn77.com in Zurich
                        4  google-zur.cdn77.com
                        6  destination reached
Timeouts:               hop 5 gave no reply
Observed providers:     DataPacket, CDN77, Google

Note on this section:
                        The traceroute file saved with this task was empty, so
                        no route was captured the first time round. I ran it
                        again afterwards on a different machine. That machine
                        resolved google.com to a different address than dig had
                        earlier, so the route above is not the route from the
                        original host. This section should be run again on the
                        machine that produced the dig output:

                          traceroute google.com | tee "traceroute output"


5. SUMMARY
----------

DNS observations:

  DNSSEC is not turned on. Without it a resolver cannot check that the answers
  it receives are genuine. That is not something an attacker can use on its own,
  but it takes away one layer of protection.

  The TXT records give away part of the supplier list. Fourteen of them name an
  outside service the company has signed up to. Anyone can read these, and in a
  real assessment they are a good starting point for working out what else is
  worth looking at.

  SPF ends in ~all, which is a soft fail. A hard fail (-all) would be stricter.
  DMARC makes up for it though, as it is set to p=reject.

  There is one MX record and all four nameservers belong to the same company.
  That works fine day to day but leaves no second provider to fall back on.

  All the answers came out of the router's cache rather than from Google's
  nameservers directly, so they show what was cached at the time.

IP observations:

  142.251.39.206 sits inside the range 142.250.0.0 to 142.251.255.255, which is
  registered to Google LLC in the United States. The address is Google's own
  rather than a rented server or an outside CDN.

  The domain answers on both IPv4 and IPv6. This is easy to forget, and firewall
  rules and scan scopes are often written for IPv4 only and miss the IPv6 side
  completely.

  The TTL on the A record was very short, so the address changes often. The one
  recorded here is only one of many.

HTTP observations:

  No HSTS header came back. On most targets a missing HSTS header is a low
  severity finding and would go in the report.

  X-Content-Type-Options, Referrer-Policy and Permissions-Policy are all missing
  as well.

  There is a Content-Security-Policy, but it is set to Report-Only. That means
  the browser reports problems back but does not actually block anything.

  X-Frame-Options is set to SAMEORIGIN, which helps against clickjacking.

  The Server header only says gws with no version number. Hiding the version is
  good practice as it gives less away about what is running.

  X-XSS-Protection is set to 0. This looks wrong at first but it is deliberate
  and correct. The old browser XSS filter caused problems of its own and modern
  browsers have dropped it. Scanners often flag this, and they are wrong to.

  Two cookies were set before logging into anything, but both have the right
  flags on them.

Network observations:

  The route goes out through carrier NAT, then DataPacket, then CDN77 in Zurich
  before reaching Google.

  Hop 5 gave no reply. This is normal. Plenty of routers are set not to answer
  traceroute, and a silent hop does not mean something is being blocked.

  Traceroute only shows one route out of several possible ones, and the traffic
  may well take a different path next time.

  The trace itself has a problem with it, explained in the note in section 4.


6. LIMITATIONS
--------------
- WHOIS information may be privacy-protected.
- DNS may point to shared/CDN/cloud infrastructure.
- Traceroute does not necessarily reveal the complete physical path.
- HTTP headers can change over time.
- The DNS answers came from a cache, not from the nameservers themselves.
- The traceroute was run from a different machine and needs running again.
- This is one snapshot of a large site that is spread across many servers.
  Someone running the same commands in another country would get different
  addresses and possibly different headers.
- Passive lookups only. No port scanning or vulnerability testing was done, so
  nothing here says anything about what services are running or how they behave.
