RECON WORKSHEET
================

Target:                 google.com
Date:                   2026-09-04 (collection), 2026-09-04 (write-up)
Authorization/source:   Training exercise (TriosCyber Task 4). Passive/OSINT
                        reconnaissance only against a public internet-facing
                        domain. No scanning, no authentication attempts, no
                        payloads sent. All data below is either public registry
                        data or a normal client request that any browser makes.

Evidence files (Task 4 folder):
  - whois output       (registry + registrar WHOIS, 7.0 KB)
  - dig output         (A, AAAA, NS, MX, TXT, 4.7 KB)
  - nslookup output    (A + AAAA, 183 B)
  - traceroute output  (0 bytes -- EMPTY, no data was captured)
  - HTTP headers       (NOT PRESENT in the folder)

Sections 3 and 4 were re-collected on 2026-09-04 to fill those two gaps. See
the "Collection notes" under each of those sections -- they were run from a
different network than the original dig/nslookup, and that matters.

------------------------------------------------------------------------------
1. WHOIS
--------
Registrar:          MarkMonitor, Inc. (IANA ID 292)
                    Registrar WHOIS server: whois.markmonitor.com
                    Abuse contact: abusecomplaints@markmonitor.com / +1.2086851750

Creation date:      1997-09-15
                    Registry record says 04:00:00Z; registrar record says
                    07:00:00 +0000. Same calendar day, 3 hours apart.

Expiration date:    2028-09-14T04:00:00Z  (registry / VeriSign)
                    2028-09-13T07:00:00+0000 (registrar / MarkMonitor)
                    The two sources disagree by one day.

Updated date:       2019-09-09 (registry) vs 2024-08-02 (registrar)
                    Five-year gap between the two "last updated" values.

Nameservers:        ns1.google.com
                    ns2.google.com
                    ns3.google.com
                    ns4.google.com
                    (All four in-bailiwick -- the nameservers live inside the
                    domain they serve, so glue records are required.)

Domain status:      clientDeleteProhibited
                    clientTransferProhibited
                    clientUpdateProhibited
                    serverDeleteProhibited
                    serverTransferProhibited
                    serverUpdateProhibited
                    (All six EPP locks set -- both the registrar-side and the
                    registry-side locks. This is the strongest standard
                    anti-hijack configuration available.)

Registrant:         Google LLC, US. Contact email is behind a MarkMonitor
                    web form, not published in the record.

DNSSEC:             unsigned  (stated in both the registry and registrar records)

------------------------------------------------------------------------------
2. DNS
-------
Resolver used:      192.168.1.1 (local gateway / ISP-forwarding resolver)
                    Answers are marked "Non-authoritative" -- these are cached
                    recursive answers, not answers straight from ns1-4.google.com.

A:                  142.251.39.206          (TTL 18)

AAAA:               2a00:1450:4007:809::200e (TTL 139)

NS:                 ns1.google.com          (TTL 1732)
                    ns2.google.com
                    ns3.google.com
                    ns4.google.com

MX:                 10  smtp.google.com     (TTL 114)
                    Only one MX host, at a single priority.

TXT:                17 records returned (TTL 300). Grouped by purpose:

  Mail policy (1):
    "v=spf1 include:_spf.google.com ~all"

  Domain-ownership proofs for third-party SaaS (14):
    google-site-verification=  x3 (TV9-DBe4..., 4ibFUgB..., wD8N7i1J...)
    docusign=                  x2 (1b0a6754..., 05958488...)
    onetrust-domain-verification= x2 (6d685f1d..., 0d477fe6...)
    facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95
    apple-domain-verification=30afIBcvSuDV2PLX
    MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB   (Microsoft 365)
    globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=
    cisco-ci-domain-verification=47c38bc8...
    arcules-domain-verification=2R4t5G7n...
    work-accounts-domain-verification=Tcj6JjIMZOw2KsSEw2Nt2rLae89tN6

  Unlabelled / opaque (2):
    "_r4rd1pvwyrpi7sw4a3hzmw8e51yh9td"
    "Z29vZ2xl"   -- this is base64; it decodes to the string "google"

Not in the captured dig output, checked separately on 2026-09-04:
  _dmarc.google.com TXT = "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"

------------------------------------------------------------------------------
3. HTTP
--------
Collection note: no HTTP evidence existed in the Task 4 folder. Headers below
were captured on 2026-09-04 with `curl -sSI` from the analysis environment,
not from the same host that produced the dig/nslookup output.

Request that succeeded: HEAD https://www.google.com

Status:             HTTP/2 200
Server:             gws   (Google Web Server -- version deliberately omitted)
Content-Type:       text/html; charset=ISO-8859-1
Cache-Control:      private
                    Expires header equals the Date header (2026-09-04 15:39:32
                    GMT), which is the classic "treat as already expired" trick.
HSTS:               NOT PRESENT. No Strict-Transport-Security header was
                    returned on this response.

Other security headers:
    x-frame-options: SAMEORIGIN                     -- present
    x-xss-protection: 0                             -- present, explicitly OFF
    content-security-policy-report-only: ...        -- REPORT-ONLY, not enforcing
        object-src 'none'; base-uri 'self';
        script-src 'nonce-...' 'strict-dynamic' 'report-sample'
                   'unsafe-eval' 'unsafe-inline' https: http:;
        report-uri https://csp.withgoogle.com/csp/gws/other-hp
    alt-svc: h3=":443"; ma=2592000, h3-29=":443"; ma=2592000  -- HTTP/3 offered
    accept-ch: Sec-CH-Prefers-Color-Scheme          -- client hints requested
    p3p: CP="This is not a P3P policy! ..."         -- legacy IE compat stub

Missing (not returned at all):
    Strict-Transport-Security
    X-Content-Type-Options
    Referrer-Policy
    Permissions-Policy
    An enforcing Content-Security-Policy

Cookies set on a plain unauthenticated HEAD request:
    AEC             -- expires 2027-03-03, Secure, HttpOnly, SameSite=lax
    __Secure-ENID   -- expires 2027-10-05, Secure, HttpOnly, SameSite=lax
    Both scoped to domain=.google.com (all subdomains).

Failed request -- worth recording rather than hiding:
    HEAD https://google.com returned
    curl: (60) SSL: no alternative certificate subject name matches target
    hostname 'google.com'
    This is almost certainly an artifact of the collection environment, not a
    real TLS misconfiguration on Google's side. In this environment the name
    google.com resolved to 8.8.8.8 (see section 4), and the certificate on
    8.8.8.8 is issued for dns.google -- so the name on the certificate did not
    match the name requested. From a normal network this request returns a
    redirect to https://www.google.com. Flagged as unverified; needs re-testing
    from the original host before it could ever be written up as a finding.

------------------------------------------------------------------------------
4. NETWORK PATH
---------------
Collection note: the traceroute output file in the Task 4 folder is 0 bytes --
the command was started but no output was ever saved. The trace below was run
fresh on 2026-09-04 from the analysis environment. Read the caveat at the end
of this section before using it; this is NOT the path from the original host.

Traceroute tool:    traceroute (/usr/sbin/traceroute), ICMP/UDP default mode,
                    -m 20 -w 2.
                    tracepath and mtr were not installed on this host.

Approximate hops:   6 hops to a responding destination.

Notable hops:
    1  100.64.5.91                                    -- CGNAT space (RFC 6598)
    2  unn-169-150-197-188.datapacket.com             -- DataPacket
    3  vl202.zur-itx1-core-2.cdn77.com (138.199.0.180)
       vl203.zur-itx1-core-1.cdn77.com (138.199.0.182) -- CDN77 core, Zurich
    4  google-zur.cdn77.com (37.19.192.35 / .47)      -- CDN77-to-Google peering
    5  * * *                                          -- no response
    6  8.8.8.8                                        -- destination reached

Timeouts:           One hop, hop 5, returned "* * *" for all three probes.
                    Load-balancing was visible at hops 3 and 4: the three
                    probes for a single hop came back from two different
                    addresses each time.

Observed providers/networks:
    - CGNAT / carrier-grade NAT at the first hop (100.64.0.0/10)
    - DataPacket (hosting / transit)
    - CDN77 backbone, Zurich exchange ("zur-itx1")
    - Google (final hop)

    Latency was flat at roughly 59-67 ms across every single hop including
    hop 1, which is the signature of a tunnel: the first hop is already
    remote, so all the real network distance is hidden inside it.

IMPORTANT CAVEAT -- this trace does not describe your network:
    traceroute here resolved google.com to 8.8.8.8. Your own dig and nslookup
    output resolved google.com to 142.251.39.206. Those are different hosts;
    8.8.8.8 is Google Public DNS, not the google.com web front end. So this
    trace measured the path to a different destination, across a different
    (tunnelled) network, than the one your DNS evidence describes. To complete
    this section properly, re-run it on the machine that produced the dig
    output and save the output this time:

        traceroute -m 30 google.com | tee "traceroute output"
        traceroute -I 142.251.39.206 | tee "traceroute output.icmp"

------------------------------------------------------------------------------
5. SUMMARY
----------

DNS observations:
  1. DNSSEC is unsigned. Both the registry and the registrar record confirm it.
     For a domain of this profile that is the single most notable gap in the
     DNS configuration -- responses cannot be cryptographically validated by a
     resolver, so a resolver-level spoofing or cache-poisoning attack has one
     fewer control standing in its way. Observation, not an exploitable finding
     in itself.
  2. The 17 TXT records leak a partial vendor list. Each verification string is
     public proof that the organisation has (or has had) a tenancy with that
     provider: Microsoft 365, Facebook/Meta Business, Apple, DocuSign, OneTrust,
     Cisco, GlobalSign, Arcules. For a real engagement this is genuinely useful
     -- it maps third-party attack surface and gives a phishing pretext list --
     and stale entries for vendors no longer in use are a known source of
     subdomain/service takeover leads. Worth checking whether every one of these
     is still an active relationship.
  3. "Z29vZ2xl" base64-decodes to "google". Harmless here, but the habit of
     decoding every opaque TXT string is the right one -- this is exactly where
     accidentally-published internal identifiers turn up.
  4. Mail path is tightly held: one MX (smtp.google.com), SPF present, and a
     DMARC policy of p=reject with aggregate reporting. SPF ends in ~all
     (softfail) rather than -all (hardfail), but p=reject in DMARC is the
     stronger control and it overrides that concern in practice.
  5. All four nameservers are in-bailiwick and all sit under one organisation.
     Single-operator DNS is a resilience consideration, not a vulnerability.
  6. All answers were non-authoritative cached responses from 192.168.1.1.
     TTLs on the A record were very short (18s remaining of a 300s record),
     which is normal for a large load-balanced/geo-steered service and means
     the observed IP is one of many and will rotate.

IP observations:
  1. A record 142.251.39.206 sits in NetRange 142.250.0.0 - 142.251.255.255,
     NetName GOOGLE, OrgName Google LLC, country US. So the address is directly
     Google-owned, not a third-party CDN or hosting reseller.
  2. The AAAA 2a00:1450:4007:809::200e is in 2a00:1450::/32, Google's European
     allocation (RIPE region), while the IPv4 registration is a US ARIN record.
     The two address families are being answered from differently-registered
     space, which is what a global anycast/geo-steered front end looks like.
  3. Both an A and an AAAA exist, so the service is dual-stack. In a real
     assessment that doubles the target set -- IPv6 endpoints are routinely
     left out of firewall rules and scan scopes that were written for IPv4.

HTTP observations:
  1. No HSTS header on the response captured. In Google's case the domain is on
     the browser HSTS preload list, so browsers enforce HTTPS regardless -- but
     for any normal target, a missing Strict-Transport-Security header is a
     legitimate low-severity finding and would be reported as one. Recording it
     here as observed-and-explained rather than silently dropping it.
  2. CSP is Report-Only, so it blocks nothing. And even if it were enforcing,
     the script-src list contains 'unsafe-inline', 'unsafe-eval', and both
     https: and http: -- that combination is close to no restriction at all
     for script execution. The 'nonce-...' + 'strict-dynamic' pair is the part
     actually doing work in modern browsers; the rest is fallback for old ones.
  3. X-Content-Type-Options: nosniff is absent. Referrer-Policy and
     Permissions-Policy are also absent. These are the standard "missing
     security headers" set that a beginner-level report should list.
  4. x-xss-protection: 0 deliberately disables the legacy browser XSS auditor.
     This is current best practice, not a weakness -- the old auditor
     introduced its own bugs and is removed from modern browsers. Do not
     report this as a finding; scanners frequently do, and they are wrong.
  5. Server: gws with no version string. Good practice -- nothing to fingerprint
     a patch level against.
  6. Two long-lived tracking cookies are set before any login. Both carry
     Secure, HttpOnly and SameSite=lax, so the flags are correct; the privacy
     question is separate from the security one.
  7. HTTP/2 negotiated, HTTP/3 advertised via alt-svc. Anything scanning only
     HTTP/1.1 will produce an incomplete picture of this host.

Network observations:
  1. The captured trace is unusable as evidence for this target and is recorded
     as such. It resolved to 8.8.8.8 rather than the 142.251.39.206 established
     in section 2, so it traced a different destination entirely.
  2. The path it did trace goes out through CGNAT, DataPacket and CDN77's
     Zurich core before peering into Google -- an egress path that belongs to
     the analysis environment, not to the original collection host.
  3. Flat ~60 ms latency starting at hop 1 indicates a tunnel/VPN egress. That
     is a useful pattern to recognise: when hop 1 already costs 60 ms, the
     local network is not what is being measured.
  4. Hop 5 timed out while hop 6 answered. This is normal -- routers commonly
     rate-limit or suppress ICMP TTL-exceeded replies. A silent hop is not a
     blocked hop, and it is not a firewall finding.
  5. Hops 3 and 4 answered from more than one address per hop, showing ECMP
     load balancing. Traceroute reports one path through a mesh, not the path.
  6. Section 4 stays OPEN until re-run on the original host.

Overall posture note (training framing):
    Nothing here is an exploitable vulnerability, and nothing should be written
    up as one. The realistic deliverables from this exercise are: DNSSEC not
    deployed, an enumerable third-party vendor list from TXT records, and the
    standard missing-header set (HSTS / nosniff / Referrer-Policy) with the
    honest caveat that preloading and Report-Only CSP change how much those
    actually matter for this specific target. The more valuable outcome is the
    process discipline -- two of the six data sources for this worksheet were
    missing or wrong, and catching that is the actual lesson.

------------------------------------------------------------------------------
6. LIMITATIONS
--------------
- WHOIS information may be privacy-protected.
- DNS may point to shared/CDN/cloud infrastructure.
- Traceroute does not necessarily reveal the complete physical path.
- HTTP headers can change over time.

Additional limitations specific to this collection:
- The traceroute file in the Task 4 folder was empty (0 bytes); no network-path
  evidence was actually captured during the original exercise.
- No HTTP evidence was captured during the original exercise at all.
- Sections 3 and 4 were therefore collected later, from a different host on a
  different (tunnelled) network, and section 4's result is not valid for this
  target. Both sections are marked with collection notes; section 4 needs to be
  re-run before this worksheet is complete.
- All DNS answers were non-authoritative and came from a caching resolver at
  192.168.1.1. No query was made directly to ns1-ns4.google.com, so the values
  recorded are what the cache held, not necessarily what the zone contains.
- The registry and registrar WHOIS records disagree on the updated date (2019
  vs 2024), the expiry date (by one day), and the creation timestamp (by three
  hours). Where they conflict, the registry (VeriSign) record is authoritative
  for registry-level fields.
- A single point-in-time snapshot of a heavily load-balanced, geo-steered
  service. The A record's TTL was 300s; the observed IP is one of many and
  another observer in another country would see different addresses, different
  headers, and a different path.
- The TLS/certificate error on https://google.com is unverified and attributed
  to the collection environment. It is not a finding until reproduced from a
  clean network.
- Passive reconnaissance only. No port scanning, service enumeration,
  vulnerability scanning, or authentication testing was performed, so nothing
  here says anything about what services are listening or how they behave.
