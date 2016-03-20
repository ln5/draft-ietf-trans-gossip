---
title: Gossiping in CT
docname: draft-ietf-trans-gossip-02-dev
category: exp
pi: [toc, sortrefs, symrefs]
ipr: trust200902
area: Security
wg: TRANS
kw: Internet-Draft

author:
  -
    ins: L. Nordberg
    name: Linus Nordberg
    email: linus@nordu.net
    org: NORDUnet
  -
    ins: D. Gillmor
    name: Daniel Kahn Gillmor
    email: dkg@fifthhorseman.net
    org: ACLU
  -
    ins: T. Ritter
    name: Tom Ritter
    email: tom@ritter.vg

normative:
  RFC-6962-BIS-09:
    title: "Certificate Transparency"
    author:
      -
        ins: B. Laurie
      -
        ins: A. Langley
      -
        ins: E. Kasper
      -
        ins: E. Messeri
      -
        ins: R. Stradling
    date: 2015-10-13
    target: https://datatracker.ietf.org/doc/draft-ietf-trans-rfc6962-bis/
  RFC7159:

--- abstract

The logs in Certificate Transparency are untrusted in the sense that
the users of the system don't have to trust that they behave correctly
since the behaviour of a log can be verified to be correct.

This document tries to solve the problem with logs presenting a "split
view" of their operations. It describes three gossiping mechanisms for
Certificate Transparency: SCT Feedback, STH Pollination and Trusted
Auditor Relationship.

--- middle

# Introduction

The purpose of the protocols in this document, collectively referred
to as CT Gossip, is to detect certain misbehavior by CT logs. In
particular, CT Gossip aims to detect logs that are providing
inconsistent views to different log clients, and logs failing to include
submitted certificates within the time period stipulated by MMD.

\[TODO: enumerate the interfaces used for detecting misbehaviour?\]

One of the major challenges of any gossip protocol is limiting damage
to user privacy. The goal of CT gossip is to publish and distribute
information about the logs and their operations, but not to expose any
additional information about the operation of any of the other
participants. Privacy of consumers of log information (in particular,
of web browsers and other TLS clients) should not be undermined by
gossip.

This document presents three different, complementary mechanisms for
non-log elements of the CT ecosystem to exchange information about
logs in a manner that preserves the privacy of HTTPS clients. They
should provide protective benefits for the system as a whole even if
their adoption is not universal.

# Defining the problem

When a log provides different views of the log to different clients
this is described as a partitioning attack. Each client would be able
to verify the append-only nature of the log but, in the extreme case,
each client might see a unique view of the log.

The CT logs are public, append-only and untrusted and thus have to be
monitored for consistency, i.e., they should never rewrite history.
Additionally, monitors and other log clients need to exchange
information about monitored logs in order to be able to detect a
partitioning attack (as described above).

Gossiping about log behaviour helps address the problem of
detecting malicious or compromised logs with respect to a partitioning
attack. We want some side of the partitioned tree, and ideally both
sides, to see the other side.

Disseminating information about a log poses a potential threat to the
privacy of end users. Some data of interest (e.g. SCTs) is linkable
to specific log entries and thereby to specific websites, which makes
sharing them with others a privacy concern. Gossiping about this data
has to take privacy considerations into account in order not to expose
associations between users of the log (e.g., web browsers) and
certificate holders (e.g., web sites). Even sharing STHs (which do not
link to specific log entries) can be problematic -- user tracking by
fingerprinting through rare STHs is one potential attack (see
{{sth-pollination}}).

# Overview

SCT Feedback enables HTTPS clients to share Signed Certificate
Timestamps (SCTs) (Section 3.3 of {{RFC-6962-BIS-09}}) with CT
auditors in a privacy-preserving manner by sending SCTs to originating
HTTPS servers, who in turn share them with CT auditors.

In STH Pollination, HTTPS clients use HTTPS servers as pools to share
Signed Tree Heads (STHs) (Section 3.6 of {{RFC-6962-BIS-09}}) with
other connecting clients in the hope that STHs will find their way to
auditors and monitors.

HTTPS clients in a Trusted Auditor Relationship share SCTs and STHs
with trusted auditors or monitors directly, with expectations of
privacy sensitive data being handled according to whatever privacy
policy is agreed on between client and trusted party.

Despite the privacy risks with sharing SCTs there is no loss in
privacy if a client sends SCTs for a given site to the site
corresponding to the SCT. This is because the site's logs would
already indicate that the client is accessing that site. In this way a
site can accumulate records of SCTs that have been issued by various
logs for that site, providing a consolidated repository of SCTs that
could be shared with auditors. Auditors can use this information to
detect logs that misbehave by not including certificates within the
time period stipulated by the MMD metadata.

Sharing an STH is considered reasonably safe from a privacy
perspective as long as the same STH is shared by a large number of
other log clients. This "safety in numbers" can be achieved by
allowing gossiping of STHs only of a certain "freshness", while also
refusing to gossip about STHs from logs with too high an STH issuance
frequency (see {{sth-pollination}}).

# Terminology and data flow

This document relies on terminology and data structures defined in
{{RFC-6962-BIS-09}}, including STH, SCT, Version, LogID, SCT
timestamp, CtExtensions, SCT signature, Merkle Tree Hash.

The following picture shows how certificates, SCTs and STHs flow
through a CT system with SCT Feedback and STH Pollination. It does not
show what goes in the Trusted Auditor Relationship stream.

~~~~
   +- Cert ---- +----------+
   |            |    CA    | ----------+
   |   + SCT -> +----------+           |
   v   |                           Cert [& SCT]
+----------+                           |
|   Log    | ---------- SCT -----------+
+----------+                           v
  |  ^                          +----------+
  |  |          SCT & Certs --- | Website  |
  |  |[1]           |           +----------+
  |  |[2]          STH            ^     |
  |  |[3]           v             |     |
  |  |          +----------+      |     |
  |  +--------> | Auditor  |      |  HTTPS traffic
  |             +----------+      |     |
  |             /                 |    SCT
  |            /            SCT & Certs |
Log entries   /                   |     |
  |          /                   STH   STH
  v         /[4]                  |     |
+----------+                      |     v
| Monitor  |                    +----------+
+----------+                    | Browser  |
                                +----------+

#   Auditor                        Log
[1] |--- get-sth ------------------->|
    |<-- STH ------------------------|
[2] |--- leaf hash + tree size ----->|
    |<-- index + inclusion proof --->|
[3] |--- tree size 1 + tree size 2 ->|
    |<-- consistency proof ----------|
[4] SCT, cert and STH among multiple Auditors and Monitors
~~~~

# Who gossips with whom {#who}

- HTTPS clients and servers (SCT Feedback and STH Pollination)
- HTTPS servers and CT auditors (SCT Feedback and STH Pollination)
- CT auditors and monitors (Trusted Auditor Relationship)

Additionally, some HTTPS clients may engage with an auditor who they
trust with their privacy:

- HTTPS clients and CT auditors (Trusted Auditor Relationship)

# What to gossip about and how {#whathow}

There are three separate gossip streams:

- SCT Feedback -- transporting SCTs and certificate chains from HTTPS
  clients to CT auditors/monitors via HTTPS servers.

- STH Pollination -- HTTPS clients and CT auditors/monitors using
  HTTPS servers as STH pools for exchanging STHs.

- Trusted Auditor Stream -- HTTPS clients communicating directly with
  trusted CT auditors/monitors sharing SCTs, certificate chains and
  STHs.

# Pre-Loaded vs Locally Added Anchors

Through the document, we refer to both Trust Anchors (Certificate Authorities)
and Logs. Both Logs and Trust Anchors may be locally added by an administrator.  
Unless otherwise clarified, in both cases we refer to the set of Trust Anchors 
and Logs that come pre-loaded and pre-trusted in a piece of client software.

# Gossip Mechanisms

## SCT Feedback

The goal of SCT Feedback is for clients to share SCTs and certificate
chains with CT auditors and monitors while still preserving the
privacy of the end user. The sharing of SCTs contribute to the overall
goal of detecting misbehaving logs by providing auditors and monitors
with SCTs from many vantage points, making it more likely to catch a
violation of a log's MMD or a log presenting inconsistent views.

SCT Feedback is the most privacy-preserving gossip mechanism, as it
does not directly expose any links between an end user and the sites
they've visisted to any third party.

\[Here's an alternative to that paragraph:
SCT Feedback is the most privacy-preserving gossip mechanism, as it
does not create any potential cross-origin tracking mechanisms.
\]

HTTPS clients store SCTs and certificate chains they see, and later
send them to the originating HTTPS server by posting them to a
well-known URL (associated with that server), as described in
{{feedback-clisrv}}. Note that clients will send the same SCTs and
chains to a server multiple times with the assumption that any
man-in-the-middle attack eventually will cease, and an honest server
will eventually receive collected malicious SCTs and certificate chains.

HTTPS servers store SCTs and certificate chains received from clients,
as described in {{feedback-srvop}}. They later share them with CT 
auditors by either posting them to auditors or making them available 
via a well-known URL. This is described in {{feedback-srvaud}}.

### SCT Feedback data format {#feedback-dataformat}

The data shared between HTTPS clients and servers, as well as between
HTTPS servers and CT auditors/monitors, is a JSON array {{RFC7159}}.
Each item in the array is a JSON object with the following content:

- x509_chain: An array of base64-encoded X.509 certificates. The
  first element is the end-entity certificate, the second certifies 
  the first and so on.

- sct_data: An array of objects consisting of the base64
  representation of the binary SCT data as defined in
  {{RFC-6962-BIS-09}} Section 3.3.

We will refer to this object as 'sct_feedback'.

The 'x509\_chain' element will always contain at least one element, consisting 
of the end-entity certificate to which the SCTs correspond. It may also contain 
a full chain from the leaf certificate to a trust anchor, depending on different 
circumstances as described below. 

\[TBD: Be strict about what sct_data may contain or is this sufficiently
implied by previous sections?\]

### HTTPS client to server {#feedback-clisrv}

When an HTTPS client connects to an HTTPS server, the client receives
a set of SCTs as part of the TLS handshake. SCTs are included in the TLS
handshake using one or more of the three mechanisms descrbied in {{RFC-6962-BIS-09}} section 3.4 -- in the server certificate, in a TLS extension, or in an OCSP extension. The client MUST
discard SCTs that are not signed by a log known to the client and SHOULD 
store the remaining SCTs together with a constructed, trusted certificate
chain (terminated in a pre-loaded or locally installed Trust Anchor) 
in a sct_feedback object or equivalent data structure) for later 
use in SCT Feedback.

The SCTs stored on the client MUST be keyed by the exact domain name 
the client contacted. They MUST NOT be sent to any domain not matching 
the original domain (e.g. if the original domain is sub.example.com they 
must not be sent to sub.sub.example.com or to example.com.) They MUST
NOT be sent to any Subject Alternate Names specified in the certificate.
In the case of certificates that validate multiple domain
names, the same SCT is expected to be stored multiple times.

Not following these constraints would increase the risk for two types
of privacy breaches. First, the HTTPS server receiving the SCT would
learn about other sites visited by the HTTPS client. Second, auditors
and monitors receiving SCTs from the HTTPS server would learn
information about other HTTPS servers visited by its clients.

When the client later connects to the HTTPS server it again receives a 
set of SCTs and calculates a certificate chain, and again creates a 
sct_feedback or similar object. If this object does not exactly match 
an existing object in the store, then the client MUST add this new 
object to the store, associated with the exact domain name contacted, 
as described above. An exact comparison is needed to ensure that attacks 
involving alternate paths are detected - an example of such an attack 
is described in \[TODO double-CA-compromise attack\]. However, at least 
one optimization is safe and MAY be performed. If the certificate path 
exactly matches an existing certificate path, the client may store the 
union of the SCTs from the two objects in the first (existing) object.

After connecting to the HTTPS server the subsequent time, the client MUST
send to the server sct_feedback objects in the store that are associated 
with that domain name. It is not necessary to send a sct_feedback object 
constructed from the current TLS session.

The client MUST NOT send the same set of SCTs to the same server more
often than TBD.

\[benl says: "sent to the server" only really counts if the server
presented a valid SCT in the handshake and the certificate is known to
be unrevoked (which will be hard for a MitM to sustain)\]

\[TODO: expand on rate/resource limiting motivation\]

Refer to {{pooling-policy-recommendations}} for recommendations about
strategies.

\[TODO: The above sentences that talk about the algorithm will be updated with the pooling recommendation section \]

SCTs and corresponding certificates are POSTed to the originating
HTTPS server at the well-known URL:

    https://<domain>/.well-known/ct/v1/sct-feedback

The data sent in the POST is defined in {{feedback-dataformat}}. This 
data SHOULD be sent in an already established TLS session. This makes 
it hard for an attacker to disrupt SCT Feedback without also disturbing 
ordinary secure browsing (https://). This is discussed more in {{blocking-policy-frustrating}}.

Some clients have trust anchors or logs that are locally added (e.g. by an
administrator or by the user themselves). These additions are
potentially privacy-sensitive because they can carry information about the
specific configuration, computer, or user. 

Certificates validated by locally added trust anchors will commonly have no 
SCTs associated with them, so in this case no action is needed with respect 
to CT Gossip. SCTs issued by locally added logs MUST NOT be reported via SCT 
Feedback.

If a certificate is validated by SCTs that are issued by publicly trusted logs, but 
chains to a local trust anchor, the client MAY perfom SCT Feedback 
for this SCT and certificate chain bundle. If it does so, the client MUST
include the full path of certificates chaining to the local trust anchor in
the x509\_chain array. Perfoming SCT Feedback in this scenario may be 
advantageous for the broader Internet and CT ecosystem, but may also disclose 
information about the client. If the client elects to omit SCT Feedback, it can 
still choose to perform STH Pollination after fetching an inclusion proof, 
as specified in  {{sth-pollination}}.

We require the client to send the full path (or nothing at all) for two 
reasons. Firstly, it simplifies the operation on the server if there are 
not two code paths. Secondly, omitting the chain does not actually preserve
user privacy. The Issuer field in the certificate describes the signing 
certificate. And if the certificate is being submitted at all, it means the 
certificate is logged, and has SCTs. This means that the Issuer can be queried
and obtained from the log - so omitting from the client's submission does
not actually help user privacy.

If the HTTPS client has configuration options for not sending cookies
to third parties, SCTs of third parties MUST be treated as cookies
with respect to this setting. This prevents third party tracking
through the use of SCTs/certificates, which would bypass the cookie
policy.

\[ TBD: We're thinking about reversing this decision \]

### HTTPS server operation {#feedback-srvop}

HTTPS servers can be configured (or omit configuration), resulting
in, broadly, two modes of operation. In the simpler mode, the server
will only track leaf certificates and SCTs applicable to those 
leaf certificates. In the more complex mode, the server will confirm 
the client's path validation and store the certificate path. The 
latter mode requires more configuration, but is necessary to prevent denial of service (DoS)
attacks on the server's storage space.  

In the simple mode of operation, upon recieving a submission at the 
sct-feedback well-known URL, a HTTPS server will perform a set of 
operations, checking on each sct_feedback object before storing it:

  1. the HTTPS server MAY modify the sct_feedback object, and discard 
  all items in the x509\_chain array except the first item (which is 
  the end-entity certificate)

  1. if a bit-wise compare of the sct_feedback object matches
  one already in the store, this sct_feedback object SHOULD be discarded

  1. if the leaf cert is not for a domain for which the server is
  authoritative, the SCT MUST be discarded

  1. if a SCT in the sct_data array can't be verified to be a valid SCT 
  for the accompanying leaf cert, and issued by a known log, the individual 
  SCT SHOULD be discarded

The modification in step number 1 is necessary to prevent a malicious client 
from exhausting the server's storage space. A client can generate their own
issuing certificate authorities, and create an arbitrary number of chains
that terminate in an end-entity certificate with an existing SCT. By 
discarding all but the end-entity certificate, we prevent a simple HTTPS
server from storing this data. Note that operation in this mode will not
prevent the attack described in \[TODO double-CA-compromise attack\]. 
Skipping this step requires additional configuration as described below.

The check in step 2 is for detecting duplicates and minimizing processing
and storage by the server. As on the client, an exact comparison is 
needed to ensure that attacks involving alternate paths are detected. 
Again, at least one optimization is safe and MAY be performed. If the 
certificate path exactly matches an existing certificate path, the server 
may store the union of the SCTs from the two objects in the first 
(existing) object. It should do this after completing the validity check 
on the SCTs.

The check in step 3 is to help malfunctioning clients from exposing which
sites they visit. It additionally helps prevent DoS attacks on the server.

\[ TBD: Thinking about building this - how does the SCT Feedback app know
which sites it's authoritative for? \]

The check in step 4 is to prevent DoS attacks where an
adversary fills up the store prior to attacking a client (thus 
preventing the client's feedback from being recorded), or an attack
where an adversary simply attempts to fill up server's storage space.

The more advanced server configuration will detect the \[TODO double-CA-compromise attack\]
attack. In this configuration the server will not modify the sct_feedback
object prior to performing checks 2, 3, and 4. 

To prevent a malicious client from filling the server's data store, the 
HTTPS Server SHOULD perform an additional check:

   5. if the x509\_chain consists of an invalid certificate chain, or the
   culminating trust anchor is not recognized by the server, the server
   SHOULD modify the sct_feedback object, discarding all items in the 
   x509\_chain array except the first item

The HTTPS server may choose to omit checks 4 or 5. This will place the 
server at risk of having its data store filled up by invalid data, but 
can also allow a server to identify interesting certificate or certificate 
chains that omit valid SCTs, or do not chain to a trusted root. This 
information may enable a HTTPS server operator to detect attacks or 
unusual behavior of Certificate Authorities even outside the Certificate 
Transparency ecosystem.

### HTTPS server to auditors {#feedback-srvaud}

HTTPS servers receiving SCTs from clients SHOULD share SCTs and
certificate chains with CT auditors by either serving them on the
well-known URL:

    https://<domain>/.well-known/ct/v1/collected-sct-feedback

or by HTTPS POSTing them to a set of preconfigured auditors. This
allows an HTTPS server to choose between an active push model or a
passive pull model.

The data received in a GET of the well-known URL or sent in the POST
is defined in {{feedback-dataformat}}. 

HTTPS servers SHOULD share all sct_feedback objects they see that 
pass the checks in {{feedback-srvop}}. If this is an infeasible 
amount of data, the server may choose to expire submissions according 
to an undefined policy. Suggestions for such a policy can be found 
in {{pooling-policy-recommendations}}.

HTTPS servers MUST NOT share any other data that they may learn from
the submission of SCT Feedback by HTTPS clients, like the HTTPS client
IP address or the time of submission.

As described above, HTTPS servers can be configured (or omit 
configuration), resulting in two modes of operation. In one mode, 
the x509\_chain array will contain a full certificate chain. This chain may 
terminate in a trust anchor the auditor may recognize, or it may not.
(One scenario where this could occur is if the client submitted a 
chain terminiating in a locally added trust anchor, and the server 
kept this chain.) In the other mode, the x509\_chain array will
consist of only a single element, which is the end-entity certificate.

Auditors SHOULD provide the following URL accepting HTTPS POSTing of
SCT feedback data:

    https://<auditor>/ct/v1/sct-feedback

\[ TBD: Should that be .well-known? \]

Auditors SHOULD regularly poll HTTPS servers at the well-known
collected-sct-feedback URL. The frequency of the polling and how to
determine which domains to poll is outside the scope of this
document. However, the selection MUST NOT be influenced by potential
HTTPS clients connecting directly to the auditor. For example, if a
poll to example.com occurs directly after a client submits an SCT for
example.com, an adversary observing the auditor can trivially conclude
the activity of the client.

## STH pollination {#sth-pollination}

The goal of sharing Signed Tree Heads (STHs) through pollination is to
share STHs between HTTPS clients, CT auditors, and monitors while
still preserving the privacy of the end user. The sharing of STHs
contribute to the overall goal of detecting misbehaving logs by
providing CT auditors and monitors with STHs from many vantage points,
making it possible to detect logs that are presenting inconsistent
views.

HTTPS servers supporting the protocol act as STH pools. HTTPS clients and
\[CT auditors and monitors\] in the possession of STHs should
pollinate STH pools by sending STHs to them, and retrieving new STHs
to send to other STH pools. CT auditors and monitors should perform
their auditing and monitoring duties by retrieving STHs from pools.

HTPS clients send STHs to HTTPS servers by POSTing them to the
well-known URL:

    https://<domain>/.well-known/ct/v1/sth-pollination

The data sent in the POST is defined in {{sth-pollination-dataformat}}. 
This data SHOULD be sent in an already established TLS session. This 
makes it hard for an attacker to disrupt STH gossiping without also 
disturbing ordinary secure browsing (https://). This is discussed more 
in {{blocking-policy-frustrating}}.

The response contains zero or more STHs in the same format, described
in {{sth-pollination-dataformat}}.

An HTTPS client may acquire STHs by several methods:

- in replies to pollination POSTs;
- asking logs that it recognises for the current STH, either directly
  (v2/get-sth) or indirectly (for example over DNS)
- resolving an SCT and certificate to an STH via an inclusion proof
- resolving one STH to another via a consistency proof

HTTPS clients (who have STHs), CT auditors, and monitors SHOULD
pollinate STH pools with STHs. Which STHs to send and how often
pollination should happen is regarded as undefined policy with the
exception of privacy concerns explained in the next
section. Suggestions for the policy may be found in
{{pooling-policy-recommendations}}.

An HTTPS client could be tracked by giving it a unique or rare STH.
To address this concern, we place restrictions on different components
of the system to ensure an STH will not be rare.

- HTTPS clients sliently ignore STHs from logs with an STH issuance
  frequency of more than one STH per hour. Logs use the STH Frequency
  Count metadata to express this ({{RFC-6962-BIS-09}} sections 3.6
  and 5.1).
- HTTPS clients silently ignore STHs which are not fresh.

An STH is considered fresh iff its timestamp is less than 14 days in
the past. Given a maximum STH issuance rate of one per hour, an
attacker has 336 unique STHs per log for tracking. Clients MUST ignore
STHs older than 14 days. We consider STHs within this validity window
not to be personally identifiable data, and STHs outside this window
to be personally identifiable.

A log may cease operation, in which case there will soon be no STH
within the validity window. Clients SHOULD perform all three methods
of gossip about a log that has ceased operation - it is possible the
log was still compromised and gossip can detect that. STH Pollination
is the one mechanism where a client must know about a log shutdown. A
client who does not know about a log shutdown MUST NOT attempt any
heuristic to detect a shutdown. Instead the client MUST be informed
about the shutdown from a verifiable source (e.g. a software
update). The client SHOULD be provided the final STH issued by the log
and SHOULD resolve SCTs and STHs to this final STH. If an SCT or STH
cannot be resolved to the final STH, clients should follow the 
requirements and recommendations set forth in {#blocking-policy-response}.

When multiplied by the number of logs from which a client accepts
STHs, this number of unique STHs grow and the negative privacy
implications grow with it. It's important that this is taken into
account when logs are chosen for default settings in HTTPS
clients. This concern is discussed upon in
{{privacy-sth-interaction}}.

### HTTPS Clients and Proof Fetching {#clients-proof-fetching}

There are two types of proofs a client may retrieve; inclusion proofs
and consistency proofs.

An HTTPS client will retrieve SCTs from an HTTPS server, and must
obtain an inclusion proof to an STH in order to verify the promise
made by the SCT.

An HTTPS client may also receive an SCT bundled with an inclusion proof to a
historical STH via an unspecified future mechanism. Because this
historical STH is considered personally identifiable information per
above, the client must obtain a consistency proof to a more recent
STH.

A client SHOULD perform proof fetching. A client MUST NOT perform 
proof fetching for any SCTs or STHs issued by a locally added log. 
A client MAY fetch an inclusion proof for an SCT (issued by a 
pre-loaded log) that validates a certificate chaining to a locally 
added trust anchor.

\[ TBD: Linus doesn't like this because we're mandating behavior 
that is not necessarily safe. Is it unsafe? Not sure.\]

If a client requested either proof directly from a log or auditor, it
would reveal the client's browsing habits to a third party. To
mitigate this risk, an HTTPS client MUST retrieve the proof in a
manner that disguises the client.

Depending on the client's DNS provider, DNS may provide an appropriate
intermediate layer that obfuscates the linkability between the user of
the client and the request for inclusion (while at the same time
providing a caching layer for oft-requested inclusion proofs.)

\[TODO: Add a reference to Google's DNS mechanism more proper than
http://www.certificate-transparency.org/august-2015-newsletter\]

Anonymity networks such as Tor also present a mechanism for a client
to anonymously retrieve a proof from an auditor or log.

Resolving either SCTs and STHs may result in errors. These errors
may be routine downtime or other transient errors, or they may be 
indicative of an attack. Clients should follow the requirements and
recommendations set forth in {#blocking-policy-response} when handling
these errors in order to give the CT ecosystem the greatest chance of 
detecting and responding to a compromise.

### STH Pollination without Proof Fetching

An HTTPS client MAY participate in STH Pollination without fetching
proofs. In this situation, the client receives STHs from a server,
applies the same validation logic to them (signed by a known log,
within the validity window) and will later pass them to a HTTPS server.

When operating in this fashion, the HTTPS client is promoting gossip
for Certificate Transparency, but derives no direct benefit itself. In
comparison, a client who resolves SCTs or historical STHs to recent
STHs and pollinates them is assured that if it was attacked, there is
a probability that the ecosystem will detect and respond to the attack
(by distrusting the log).

### Auditor and Monitor Action

Auditors and Monitors participate in STH pollination by retrieving
STHs from HTTPS servers. They verify that the STH is valid by checking
the signature, and requesting a consistency proof from the STH to the
most recent STH.

After retrieving the consistency proof to the most recent STH, they
SHOULD pollinate this new STH among participating HTTPS Servers. In
this way, as STHs "age out" and are no longer fresh, their "lineage"
continues to be tracked in the system.

### STH Pollination data format {#sth-pollination-dataformat}

The data sent from HTTPS clients and CT monitors and auditors to HTTPS
servers is a JSON object {{RFC7159}} with the following content:

- sths -- an array of 0 or more fresh SignedTreeHead's as defined in
  {{RFC-6962-BIS-09}} Section 3.6.1.

## Trusted Auditor Stream

HTTPS clients MAY send SCTs and cert chains, as well as STHs, directly
to auditors. If sent, this data MAY include data that reflects locally 
added logs or trust anchors. Note that there are privacy implications 
in doing so, these are outlined in {{privacy-SCT}} and
{{privacy-trusted-auditors}}.

The most natural trusted auditor arrangement arguably is a web browser
that is "logged in to" a provider of various internet
services. Another equivalent arrangement is a trusted party like a
corporation to which an employee is connected through a VPN or by
other similar means. A third might be individuals or smaller groups of
people running their own services. In such a setting, retrieving
proofs from that third party could be considered reasonable from a
privacy perspective. The HTTPS client may also do its own auditing and might
additionally share SCTs and STHs with the trusted party to contribute
to herd immunity. Here, the ordinary {{RFC-6962-BIS-09}} protocol is
sufficient for the client to do the auditing while SCT Feedback and
STH Pollination can be used in whole or in parts for the gossip part.

Another well established trusted party arrangement on the internet
today is the relation between internet users and their providers of
DNS resolver services. DNS resolvers are typically provided by the
internet service provider (ISP) used, which by the nature of name
resolving already know a great deal about which sites their users
visit. As mentioned in {{clients-proof-fetching}}, in order for HTTPS
clients to be able to retrieve proofs in a privacy preserving manner,
logs could expose a DNS interface in addition to the ordinary HTTPS
interface. An informal writeup of such a protocol can be found at XXX.


### Trusted Auditor data format

Trusted Auditors expose a REST API at the fixed URI:

    https://<auditor>/ct/v1/trusted-auditor

Submissions are made by sending a HTTPS POST request, with the body of
the POST in a JSON object. Upon successful receipt the Trusted Auditor 
returns 200 OK. 

The JSON object consists of two top-level keys: 'sct_feedback'
and 'sths'.  The 'sct_feedback' value is an array of JSON objects as 
defined in {{feedback-dataformat}}. The 'sths' value is an array of STHs
as defined in {{sth-pollination-dataformat}}.

Example:

    {
      'sct_feedback' :
        [
          {
            'x509_chain' : 
              [ 
                '----BEGIN CERTIFICATE---\n
                 AAA...',
                '----BEGIN CERTIFICATE---\n
                 AAA...', 
                 ...
              ],
            'sct_data' :
              [
                'AAA...', 
                'AAA...', 
                ...
              ]
          }, ...
        ],
      'sths' :
        [
          'AAA...', 
          'AAA...', 
          ...
        ]
    }

# 3-Method Ecosystem

The use of three distinct methods for monitoring logs may seem
excessive, but each represents a needed component in the CT
ecosystem. To understand why, the drawbacks of each component must be
outlined. In this discussion we assume that an attacker knows which
mechanisms an HTTPS client and HTTPS server implement.

## SCT Feedback

SCT Feedback requires the cooperation of HTTPS clients and more
importantly HTTPS servers. Although SCT Feedback does require a
significant amount of server-side logic to respond to the
corresponding APIs, this functionality does not require customization,
so it may be pre-provided and work out of the box. However, to take
full advantage of the system, an HTTPS server would wish to perform
some configuration to optimize its operation:

- Minimize its disk commitment by maintaining a list of known SCTs and
  certificate chains (or hashes thereof)
- Maximize its chance of detecting a misissued certificate by
  configuring a trust store of CAs
- Establish a "push" mechanism for POSTing SCTs to Auditors and
  Monitors

These configuration needs, and the simple fact that it would require
some deployment of software, means that some percentage of HTTPS
servers will not deploy SCT Feedback.

It is worthwhile to note that an attacker may be able to prevent 
detection of an attack on a webserver (in all cases) if SCT 
Feedback is not implemented. This attack is detailed in {#actively-malicious-log}).

If SCT Feedback was the only mechanism in the ecosystem, any server
that did not implement the feature would open itself and its users to
attack without any possibility of detection.

If SCT Feedback is not deployed by a webserver, malicious logs will be 
able to attack all users of the webserver (who do not have a Trusted 
Auditor relationship) with impunity. Additionally, users who wish to
have the strongest measure of privacy protection (by disabling STH 
Pollination Proof Fetching and forgoing a Trusted Auditor) could be 
attacked without risk of detection.

## STH Pollination {#threemetheco-sth-pollination}

STH Pollination requires the cooperation of HTTPS clients, HTTPS
servers, and logs.

For a client to fully participate in STH Pollination, and have this
mechanism detect attacks against it, the client must have a way to
safely perform Proof Fetching in a privacy preserving manner. (The
client may pollinate STHs it receives without performing Proof
Fetching, but we do not consider this option in this section.)

HTTPS Servers must deploy software (although, as in the case with SCT
Feedback this logic can be pre-provided) and commit some configurable
amount of disk space to the endeavor.

Logs (or a third party) must provide access to clients to query proofs
in a privacy preserving manner, most likely through DNS.

Unlike SCT Feedback, the STH Pollination mechanism is not hampered if
only a minority of HTTPS servers deploy it. However, it makes an
assumption that an HTTPS client performs Proof Fetching
(such as the DNS mechanism discussed). Unfortunately, any manner that is
anonymous for some (such as clients who use shared DNS services such
as a large ISP), may not be anonymous for others.

For instance, DNS requests expose a considerable amount of sensitive information
(including what data is already present in the cache) in plaintext
over the network. For this reason, some percentage of HTTPS clients
may choose to not enable the Proof Fetching component of STH
Pollination. (Although they can still request and send STHs among
participating HTTPS servers, even when this affords them no
direct benefit.)

If STH Pollination was the only mechanism deployed, users that disable
it would be able to be attacked without risk of detection.

If STH Pollination was not deployed, HTTPS Clients visiting HTTPS
Servers who did not deploy SCT Feedback could be attacked without risk
of detection.

## Trusted Auditor Relationship

The Trusted Auditor Relationship is expected to be the rarest gossip
mechanism, as an HTTPS Client is providing an unadulterated report of
its browsing history to a third party. While there are valid and
common reasons for doing so, there is no appropriate way to enter into
this relationship without retrieving informed consent from the user.

However, the Trusted Auditor Relationship mechanism still provides
value to a class of HTTPS Clients. For example, web crawlers have no
concept of a "user" and no expectation of privacy. Organizations
already performing network monitoring for anomalies or attacks can run
their own Trusted Auditor for the same purpose with marginal increase
in privacy concerns.

The ability to change one's Trusted Auditor is a form of Trust Agility
that allows a user to choose who to trust, and be able to revise that
decision later without consequence. A Trusted Auditor connection can
be made more confidential than DNS (through the use of TLS), and can
even be made (somewhat) anonymous through the use of anonymity
services such as Tor. (Note that this does ignore the de-anonymization
possibilities available from viewing a user's browsing history.)

If the Trusted Auditor relationship was the only mechanism deployed,
users who do not enable it (the majority) would be able to be attacked
without risk of detection.

If the Trusted Auditor relationship was not deployed, crawlers and
organizations would build it themselves for their own needs. By
standardizing it, users who wish to opt-in (for instance those
unwilling to participate fully in STH Pollination) can have an
interoperable standard they can use to choose and change their trusted
auditor.

## Interaction

The interactions of the mechanisms is thus outlined:

HTTPS Clients can be attacked without risk of detection if they do not
participate in any of the three mechanisms.

HTTPS Clients are afforded the greatest chance of detecting an attack
when they either participate in both SCT Feedback and STH Pollination 
with Proof Fetching or if they have a Trusted Auditor relationship. 
(Participating in SCT Feedback is required to prevent a malicious log
from refusing to ever resolve an SCT to an STH, as put forward in 
{#actively-malicious-log}). Additionally, participating in SCT
Feedback enables an HTTPS Client to assist in detecting the exact target 
of an attack.

HTTPS Servers that omit SCT Feedback enable malicious logs to carry out 
attacks without risk of detection. If these servers are targeted 
specifically, even if the attack is detected, without SCT Feedback they 
may never learn that they were specifically targeted. HTTPS servers 
without SCT Feedback do gain some measure of herd immunity, but only 
because their clients participate in STH Pollination (with Proof 
Fetching) or have a Trusted Auditor Relationship.

When HTTPS Servers omit SCT feedback, it allows their users to be 
attacked without detection by a malicious log; the vulnerable users are 
those who do not have a Trusted Auditor relationship.

# Security considerations

## Attacks by actively malicious logs {#actively-malicious-log}

One of the most powerful attacks possible in the CT ecosystem is a
trusted log that has actively decided to be malicious. It can carry 
out an attack in two ways:

In the first attack, the log can present a split view of the log for 
all time. The only way to detect this attack is to resolve each view 
of the log to the two most recent STHs and then force the log to present
a consistency proof. (Which it cannot.) This attack can be detected by 
Auditors or Monitors participating in STH Pollination, as long as they are
explicitly built to handle the situation of a log continuously presenting
a split view.

In the second attack, the log can sign an SCT, and refuse to ever include 
the certificate that the SCT refers to in the tree. (Alternately, it can include it in a branch of the tree and 
issue an STH, but then abandon that branch.) Whenever someone requests an 
inclusion proof for that SCT (or a consistency proof from that STH), the log 
would respond with an error, and a client may simply regard the response
as a transient error. This attack can be detected using SCT Feedback, or an 
Auditor of Last Resort, as presented in {#blocking-policy-response}.

## Censorship/Blocking considerations

We assume a network attacker who is able to fully control the client's
internet connection for some period of time - including selectively
blocking requests to certain hosts and truncating TLS connections
based on information observed or guessed about client behavior. In
order to successfully detect log misbehavior, the gossip mechanisms
must still work even in these conditions.

There are several gossip connections that can be blocked:

1. Clients sending SCTs to servers in SCT Feedback
2. Servers sending SCTs to auditors in SCT Feedback (server push mechanism)
3. Servers making SCTs available to auditors (auditor pull mechanism)
4. Clients fetching proofs in STH Pollination
5. Clients sending STHs to servers in STH Pollination
6. Servers sending STHs to clients in STH Pollination
7. Clients sending SCTs to Trusted Auditors

If a party cannot connect to another party, it can be assured that the
connection did not succeed. While it may not have been maliciously
blocked, it knows the transaction did not succeed. Mechanisms which
result in a positive affirmation from the recipient that the
transaction succeeded allow confirmation that a connection was not
blocked. In this situation, the party can factor this into strategies
suggested in {{pooling-policy-recommendations}} and in
{{blocking-policy-response}}.

The connections that allow positive affirmation are 1, 2, 4, 5, and 7.

More insidious is blocking the connections that do not allow positive
confirmation: 3 and 6. An attacker may truncate or drop a response
from a server to a client, such that the server believes it has shared
data with the recipient, when it has not. However, in both scenatios
(3 and 6), the server cannot distinguish the client as a cooperating
member of the CT ecosystem or as an attacker performing a sybil
attack, aiming to flush the server's data store. Therefore the fact
that these connections can be undetectably blocked does not actually
alter the threat model of servers responding to these requests. The
choice of algorithm to release data is crucial to protect against
these attacks; strategies are suggested in
{{pooling-policy-recommendations}}.

Handling censorship and network blocking (which is indistinguishable
from network error) is relegated to the implementation policy chosen
by clients. Suggestions for client behavior are specified in
{{blocking-policy-recommendations}}.

## Privacy considerations

CT Gossip deals with HTTPS Clients which are trying to share
indicators that correspond to their browsing history. The most
sensitive relationships in the CT ecosystem are the relationships
between HTTPS clients and HTTPS servers. Client-server relationships
can be aggregated into a network graph with potentially serious
implications for correlative de-anonymisation of clients and
relationship-mapping or clustering of servers or of clients.

There are, however, certain clients that do not require privacy
protection. Examples of these clients are web crawlers or robots -- but
even in this case, the method by which these clients crawl the web may
in fact be considered sensitive information. In general, it is better
to err on the side of safety, and not assume a client is okay with
giving up its privacy.

### Privacy and SCTs {#privacy-SCT}

An SCT contains information that links it to a particular web
site. Because the client-server relationship is sensitive, gossip
between clients and servers about unrelated SCTs is risky. Therefore,
a client with an SCT for a given server should transmit that
information in only two channels: to the server associated with the SCT
itself; and to a trusted CT auditor, if one exists.

### Privacy in SCT Feedback {#privacy-feedback}

SCTs introduce yet another mechanism for HTTPS servers to store state
on an HTTPS client, and potentially track users. HTTPS clients which
allow users to clear history or cookies associated with an origin MUST
clear stored SCTs and certificate chains associated with the origin as 
well.

Auditors should treat all SCTs as sensitive data. SCTs received
directly from an HTTPS client are especially sensitive, because the
auditor is a trusted by the client to not reveal their associations
with servers. Auditors MUST NOT share such SCTs in any way, including
sending them to an external log, without first mixing them with
multiple other SCTs learned through submissions from multiple other
clients. Suggestions for mixing SCTs are presented in
{{pooling-policy-recommendations}}.

There is a possible fingerprinting attack where a log issues a unique
SCT for targeted log client(s). A colluding log and HTTPS server
operator could therefore be a threat to the privacy of an HTTPS
client. Given all the other opportunities for HTTPS servers to
fingerprint clients -- TLS session tickets, HPKP and HSTS headers,
HTTP Cookies, etc. -- this is considered acceptable.

The fingerprinting attack described above would be mitigated by a
requirement that logs MUST use a deterministic signature scheme when
signing SCTs ({{RFC-6962-BIS-09}} Section 2.1.4). A log signing using
RSA is not required to use a deterministic signature scheme.

Since logs are allowed to issue a new SCT for a certificate already
present in the log, mandating deterministic signatures does not stop
this fingerprinting attack altogether. It does make the attack harder
to pull off without being detected though.

There is another similar fingerprinting attack where an HTTPS server
tracks a client by using a unqiue certificate or a variation of cert 
chains. The risk for this
attack is accepted on the same grounds as the unique SCT attack
described above. \[XXX any mitigations possible here?\]

### Privacy for HTTPS clients performing STH Proof Fetching

An HTTPS client performing Proof Fetching should only request proofs
from a CT log that it accepts SCTs from. An HTTPS client MAY
regularly \[TBD SHOULD? how regularly? This has operational implications for
log operators\] request an STH from all logs it is willing to accept,
even if it has seen no SCTs from that log.

The actual mechanism by which Proof Fetching is done carries
considerable privacy concerns. Although out of scope for the document,
DNS is a mechanism currently discussed. DNS exposes data in plaintext
over the network (including what sites the user is visiting and what
sites they have previously visited) - thus it may not be suitable for
some.

### Privacy in STH Pollination

An STH linked to an HTTPS client may indicate the following about that
client:

- that the client gossips;

- that the client has been using CT at least until the time that the
  timestamp and the tree size indicate;

- that the client is talking, possibly indirectly, to the log
  indicated by the tree hash;

- which software and software version is being used.

There is a possible fingerprinting attack where a log issues a unique
STH for a targeted HTTPS client. This is similar to the fingerprinting
attack described in {{privacy-feedback}}, but can operate
cross-origin. If a log (or HTTPS Server cooperating with a log)
provides a unique STH to a client, the targeted client will be the
only client pollinating that STH cross-origin.

It is mitigated partially because the log is limited in the number of
STHs it can issue. It must 'save' one of its STHs each MMD to perform
the attack.

### Privacy in STH Interaction {#privacy-sth-interaction}

An HTTPS client may pollinate any STH within the last 14 days. An
HTTPS Client may also pollinate an STH for any log that it knows
about. When a client pollinates STHs to a server, it will release
more than one STH at a time. It is unclear if a server may 'prime' a
client and be able to reliably detect the client at a later time.

It's clear that a single site can track a user any way they wish, but
this attack works cross-origin and is therefore more concerning. Two
independent sites A and B want to collaborate to track a user
cross-origin. A feeds a client Carol some N specific STHs from the M
logs Carol trusts, chosen to be older and less common, but still in
the validity window. Carol visits B and chooses to release some of the
STHs she has stored, according to some policy.

Modeling a representation for how common older STHs are in the pools
of clients, and examining that with a given policy of how to choose
which of those STHs to send to B, it should be possible to calculate
statistics about how unique Carol looks when talking to B and how
useful/accurate such a tracking mechanism is.

Building such a model is likely impossible without some real world
data, and requires a given implementation of a policy. To combat this
attack, suggestions are provided in {{pooling-policy-recommendations}}
to attempt to minimize it, but follow-up testing with real world
deployment to improve the policy will be required.

### Trusted Auditors for HTTPS Clients {#privacy-trusted-auditors}

Some HTTPS clients may choose to use a trusted auditor. This trust
relationship exposes a large amount of information about the client to
the auditor. In particular, it will identify the web sites that the
client has visited to the auditor. Some clients may already share this
information to a third party, for example, when using a server to
synchronize browser history across devices in a server-visible way, or
when doing DNS lookups through a trusted DNS resolver. For clients
with such a relationship already established, sending SCTs to a
trusted auditor run by the same organization does not appear to expose
any additional information to the trusted third party.

Clients who wish to contact an auditor without associating their
identities with their SCTs may wish to use an anonymizing network like
Tor to submit SCT Feedback to the auditor. Auditors SHOULD accept SCT
Feedback that arrives over such anonymizing networks.

Clients sending feedback to an auditor may prefer to reduce the
temporal granularity of the history exposure to the auditor by caching
and delaying their SCT Feedback reports. This is elaborated upon in 
{#pooling-policy-recommendations}. This strategy is only as effective 
as the granularity of the timestamps embedded in the SCTs and STHs.

### HTTPS Clients as Auditors

Some HTTPS Clients may choose to act as Auditors themselves. A Client
taking on this role needs to consider the following:

- an Auditing HTTPS Client potentially exposes its history to the logs
  that they query. Querying the log through a cache or a proxy with
  many other users may avoid this exposure, but may expose information to
  the cache or proxy, in the same way that an non-Auditing HTTPS
  Client exposes information to a trusted auditor.

- an effective Auditor needs a strategy about what to do in the event
  that it discovers misbehavior from a log. Misbehavior from a log
  involves the log being unable to provide either (a) a consistency
  proof between two valid STHs or (b) an inclusion proof for a
  certificate to an STH any time after the log's MMD has elapsed from
  the issuance of the SCT. The log's inability to provide either proof
  will not be externally cryptographically-verifiable, as it may be
  indistinguishable from a network error.

# Policy Recommendations

This section is intended as suggestions to implementors of HTTPS
Clients, HTTPS Servers, and Auditors. It is not a requirement for
technique of implementation, so long as privacy considerations
established above are obeyed.

## Mixing Recommendations {#pooling-policy-recommendations}

In several components of the CT Gossip ecosystem, the recommendation
is made that data from multiple sources be ingested, mixed, stored for 
an indeterminate period of time, provided (multiple times) to a third
party, and eventually deleted. The instances of these recommendations 
in this draft are:

- When a client receives SCTs during SCT Feedback, it should store the
  SCTs and Certificates for some amount of time, provide some of them
  back to the server at some point, and eventually remove them from
  its store

- When a client receives STHs during STH Pollination, it should store
  them for some amount of time, mix them with other STHs, release some
  of them them to various servers at some point, resolve some of them
  to new STHs, and eventually remove them from its store

- When a server receives SCTs during SCT Feedback, it should store
  them for some period of time, provide them to auditors some number
  of times, and may eventually remove them

- When a server receives STHs during STH Pollination, it should store
  them for some period of time, mix them with other STHs, provide some
  of them to connecting clients, may resolve them to new STHs via
  Proof Fetching, and eventually remove them from its store

- When a Trusted Auditor receives SCTs or historical STHs from
  clients, it should store them for some period of time, mix them with
  SCTs received from other clients, and act upon them at some period
  of time

Each of these instances have specific requirements for user privacy,
and each have options that may not be invoked. As one example, a HTTPS
client should not mix SCTs from server A with SCTs from server B and
release server B's SCTs to Server A. As another example, a HTTPS
server may choose to resolve several STHs to a single more current STH
via proof fetching, but it is under no obligation to do so.

These requirements should be met, but the general problem of
aggregating multiple pieces of data, choosing when and how many to
release, and when to remove is shared. This problem has been
previously been considered in the case of Mix Networks and Remailers,
including papers such as \[X\], \[Y\], and \[Z\].

Certain common recommendations can be made:

- When choosing how many times to release data before expiring it from
  a cache, use a random number chosen from a distribution, rather than
  a fixed number. This prevents an adversary from knowing with
  certainty that it has successfully flushed a cache of a potentially
  incriminating piece of data.

- \[TODO Enumerating the problems of different types of mixes vs Cottrell Mix\]
- \[TODO Integrating the IP address into the algorithm for releasing data\]
- \[TODO Prefer aggregating multiple piece of data into a single STH when
  possible\]
- \[TODO The importance of Flushing Attacks, and tying in network
  connection, and time interval\]

## Blocking Recommendations {#blocking-policy-recommendations}

### Frustrating blocking {#blocking-policy-frustrating}

When making gossip connections to HTTPS Servers or Trusted Auditors,
it is desirable to minimize the plaintext metadata in the connection
that can be used to identify the connection as a gossip connection and
therefore be of interest to block. Additionally, introducing some
randomness into client behavior may be important - we assume that the
adversary is able to inspect the behavior of the HTTPS client and
understand how it makes gossip connections.

As an example, if a client, after establishing a TLS connection (and
receiving an SCT, but not making its own HTTP request yet),
immediately opens a second TLS connection for the purpose of gossip -
the adversary can reliably block this second connection to block
gossip without affecting normal browsing. For this reason it is
recommended to run the gossip protocols over an existing connection to
the server, making use of connection multiplexing such as HTTP
Keep-Alives or SPDY.

Truncation is also a concern -if a client always establishes a TLS
connection, makes a request, receives a response, and then always
attempts a gossip communication immediately following the first
response - truncation will allow an attacker to block gossip reliably.

For these reasons, we recommend that, if at all possible, clients
SHOULD send gossip data in an already established TLS session. This
can be done through the use of HTTP Pipelining, SPDY, or HTTP/2.

### Responding to possible blocking {#blocking-policy-response}
In some cirsumstances a client may have a piece of data that they have
attempted to share (via SCT Feedback or STH Pollination), but have been 
unable to do so: with every attempt they recieve an error. These 
situations are:

1. The client has an SCT and a certificate, and attempts to retrieve an 
inclusion proof -- but recieves an error on every attempt.
2. The client has an STH, and attempts to resolve it to a newer STH via
a consistency proof -- but recieves an error on every attempt.
3. The client has attempted to share an SCT and constructed certificate
via SCT Feedback -- but recieves an error on every attempt.
4. The client has attempted to share an STH via STH Pollination -- but
recieves an error on every attempt.
5. The client has attempted to share a specific piece of data with a 
Trusted Auditor -- but recieves an error on every attempt.

In the case of 1 or 2, it is conceivable that the reason for the errors
is that the log acted improperly, either through malicious actions or 
compromise. A proof may not be able to be fetched because it does not 
exist (and only errors or timeouts occur) -- one such situation may arise 
because of an actively malicious log, as presented in {#actively-malicious-log}.
This data is especially important to share with the broader internet to 
detect this situation.

If an SCT has attempted to be resolved to an STH via an inclusion proof
multiple times, and each time has failed, a client SHOULD make every 
effort to send this SCT via SCT Feedback. However the client MUST NOT
share the data with any other third party (excepting a Trusted Auditor
should one exist). 

If an STH has attempted to be resolved to a newer STH via a consistency 
proof multiple times, and each time has failed, a client MAY share the 
STH with an "Auditor of Last Resort" even if the STH in question is no 
longer within the validity window. This auditor may be pre-configured 
by the client SHOULD permit a user to change or disable 
whom data is sent to.

In the cases 3, 4, and 5, we assume that the webserver(s) or 
trusted auditor in question is either experiencing an operational failure, 
or being attacked. In both cases, a client SHOULD retain the data for 
later submission (subject to Private Browsing or other history-clearing 
actions taken by the user.)


# IANA considerations

\[TBD\]

# Contributors

The authors would like to thank the following contributors for
valuable suggestions: Al Cutter, Ben Laurie, Benjamin Kaduk, Josef
Gustafsson, Karen Seo, Magnus Ahltorp, Steven Kent, Yan Zhu.

# ChangeLog

## Changes between ietf-00 and ietf-01

- Improve langugage and readability based on feedback from Stephen
  Kent.
- STH Pollination Proof Fetching defined and indicated as optional.
- 3-Method Ecosystem section added.
- Cases with Logs ceasing operation handled.
- Text on tracking via STH Interaction added.
- Section with some early recommendations for mixing added.
- Section detailing blocking connections, frustrating it, and the
  implications added.

## Changes between -01 and -02

- STH Pollination defined.
- Trusted Auditor Relationship defined.
- Overview section rewritten.
- Data flow picture added.
- Section on privacy considerations expanded.

## Changes between -00 and -01

- Add the SCT feedback mechanism: Clients send SCTs to originating web
  server which shares them with auditors.
- Stop assuming that clients see STHs.
- Don't use HTTP headers but instead .well-known URL's -- avoid that
  battle.
- Stop referring to trans-gossip and trans-gossip-transport-https --
  too complicated.
- Remove all protocols but HTTPS in order to simplify -- let's come
  back and add more later.
- Add more reasoning about privacy.
- Do specify data formats.
