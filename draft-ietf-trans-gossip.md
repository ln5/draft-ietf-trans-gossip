---
title: Gossiping in CT
docname: draft-ietf-trans-gossip-04
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
  RFC-6962-BIS-27:
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
    target: https://datatracker.ietf.org/doc/draft-ietf-trans-rfc6962-bis/
    date: 2017-10-30
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
  RFC7540:

informative:
  draft-ietf-trans-threat-analysis-03:
    title: "Attack Model and Threat for Certificate Transparency"
    author:
      -
        ins: S. Kent
    date: 2015-10-06
    target: https://datatracker.ietf.org/doc/draft-ietf-trans-threat-analysis/

  dual-ca-compromise-attack:
    title: "can CT defend against dual CA compromise?"
    author:
      -
        ins: D. Gillmor
    target: https://www.ietf.org/mail-archive/web/trans/current/msg01984.html

  draft-ct-over-dns:
    title: "Certificate Transparency over DNS"
    author:
      -
        ins: B. Laurie
      -
        ins: P. Phaneuf
      -
        ins: A. Eijdenberg
    date: 2016-02-18
    target: https://github.com/google/certificate-transparency-rfcs/blob/master/dns/draft-ct-over-dns.md

  double-keying:
    title: "Cross-Origin Identifier Unlinkability"
    author:
      -
        ins: M. Perry
      -
        ins: E. Clark
      -
        ins: S. Murdoch
    date: 2015-05-06
    target: https://www.torproject.org/projects/torbrowser/design/#identifier-linkability

  trickle:
    title: "From a Trickle to a Flood: Active Attacks on Several Mix Types"
    author:
      -
        ins: A. Serjantov
      -
        ins: R. Dingledine
      -
        ins: Paul Syverson
    date: 2002-10
    target: http://freehaven.net/doc/batching-taxonomy/taxonomy.pdf

  gossip-mixing:
    title: "A Bit on Certificate Transparency Gossip"
    author:
      -
        ins: T. Ritter
    date: 2016-06-27
    target: https://ritter.vg/blog-a_bit_on_certificate_transparency_gossip.html

--- abstract

The logs in Certificate Transparency are untrusted in the sense that
the users of the system don't have to trust that they behave correctly
since the behavior of a log can be verified to be correct.

This document tries to solve the problem with logs presenting a "split
view" of their operations or failing to incorporate a submission
within MMD. It describes three gossiping mechanisms for Certificate
Transparency: SCT Feedback, STH Pollination and Trusted Auditor
Relationship.

--- middle

# Introduction

The purpose of the protocols in this document, collectively referred
to as CT Gossip, is to detect certain misbehavior by CT logs. In
particular, CT Gossip aims to detect logs that are providing
inconsistent views to different log clients, and logs failing to
include submitted certificates within the time period stipulated by
MMD.

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
audited for consistency, i.e., they should never rewrite history.
Additionally, auditors and other log clients need to exchange
information about logs in order to be able to detect a partitioning
attack (as described above).

Gossiping about log behavior helps address the problem of detecting
malicious or compromised logs with respect to a partitioning
attack. We want some side of the partitioned tree, and ideally all
sides, to see at least one other side.

Disseminating information about a log poses a potential threat to the
privacy of end users. Some data of interest (e.g., SCTs) is linkable to
specific log entries and thereby to specific websites, which makes
sharing them with others a privacy concern. Gossiping about this data
has to take privacy considerations into account in order not to expose
associations between users of the log (e.g., web browsers) and
certificate holders (e.g., web sites). Even sharing STHs (which do not
link to specific log entries) can be problematic -- user tracking by
fingerprinting through rare STHs is one potential attack (see
{{sth-pollination}}).

# Overview

This document presents three gossiping mechanisms: SCT Feedback, STH
Pollination, and a Trusted Auditor Relationship.

SCT Feedback enables HTTPS clients to share Signed Certificate
Timestamps (SCTs) (Section 3.3 of {{RFC-6962-BIS-09}}) with CT
auditors in a privacy-preserving manner by sending SCTs to originating
HTTPS servers, which in turn share them with CT auditors.

In STH Pollination, HTTPS clients use HTTPS servers as pools to share
Signed Tree Heads (STHs) (Section 3.6 of {{RFC-6962-BIS-09}}) with
other connecting clients in the hope that STHs will find their way to
CT auditors.

HTTPS clients in a Trusted Auditor Relationship share SCTs and STHs
with trusted CT auditors directly, with expectations of privacy
sensitive data being handled according to whatever privacy policy is
agreed on between client and trusted party.

Despite the privacy risks with sharing SCTs there is no loss in
privacy if a client sends SCTs for a given site to the site
corresponding to the SCT. This is because the site's cookies could
already indicate that the client had accessed that site. In this way a
site can accumulate records of SCTs that have been issued by various
logs for that site, providing a consolidated repository of SCTs that
could be shared with auditors. Auditors can use this information to
detect a misbehaving log that fails to include a certificate within
the time period stipulated by its MMD metadata.

Sharing an STH is considered reasonably safe from a privacy
perspective as long as the same STH is shared by a large number of
other log clients. This safety in numbers can be achieved by only
allowing gossiping of STHs issued in a certain window of time, while
also refusing to gossip about STHs from logs with too high an STH
issuance frequency (see {{sth-pollination}}).

# Terminology

This document relies on terminology and data structures defined in
{{RFC-6962-BIS-09}}, including MMD, STH, SCT, Version, LogID, SCT
timestamp, CtExtensions, SCT signature, Merkle Tree Hash.

This document relies on terminology defined in
{{draft-ietf-trans-threat-analysis-03}}, including Auditing.

## Pre-Loaded vs Locally Added Anchors

Through the document, we refer to both Trust Anchors (Certificate
Authorities) and Logs. Both Logs and Trust Anchors may be locally
added by an administrator. Unless otherwise clarified, in both cases
we refer to the set of Trust Anchors and Logs that come pre-loaded and
pre-trusted in a piece of client software.

# Who gossips with whom {#who}

- HTTPS clients and servers (SCT Feedback and STH Pollination)
- HTTPS servers and CT auditors (SCT Feedback and STH Pollination)
- CT auditors (Trusted Auditor Relationship)

Additionally, some HTTPS clients may engage with an auditor which they
trust with their privacy:

- HTTPS clients and CT auditors (Trusted Auditor Relationship)

# What to gossip about and how {#whathow}

There are three separate gossip streams:

- SCT Feedback -- transporting SCTs and certificate chains from HTTPS
  clients to CT auditors via HTTPS servers.

- STH Pollination -- HTTPS clients and CT auditors using
  HTTPS servers as STH pools for exchanging STHs.

- Trusted Auditor Stream -- HTTPS clients communicating directly with
  trusted CT auditors sharing SCTs, certificate chains and STHs.

It is worthwhile to note that when an HTTPS client or CT auditor
interacts with a log, they may equivalently interact with a log mirror
or cache that replicates the log.

# Data flow

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
  |  |         SCTs & Certs --- | Website  |
  |  |[1]           |           +----------+
  |  |[2]         STHs            ^     |
  |  |[3]           v             |  HTTPS traffic
  |  |          +----------+      |     |
  |  +--------> | Auditor  |      |  SCT & Cert
  |             +----------+      |     |
 STH                              |  STH & Inclusion proof
  |                               |     |
Log entries                SCTs & Certs |
  |                               |     |
  v                             STHs    |
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
~~~~

# Gossip Mechanisms

## SCT Feedback

The goal of SCT Feedback is for clients to share SCTs and certificate
chains with CT auditors while still preserving the privacy of the end
user. The sharing of SCTs contribute to the overall goal of detecting
misbehaving logs by providing auditors with SCTs from many vantage
points, making it more likely to catch a violation of a log's MMD or a
log presenting inconsistent views. The sharing of certificate chains
is beneficial to HTTPS server operators interested in direct feedback
from clients for detecting bogus certificates issued in their name and
therefore incentivizes server operators to take part in SCT Feedback.

SCT Feedback is the most privacy-preserving gossip mechanism, as it
does not directly expose any links between an end user and the sites
they've visited to any third party.

HTTPS clients store SCTs and certificate chains they see, and later
send them to the originating HTTPS server by posting them to a
well-known URL (associated with that server), as described in
{{feedback-clisrv}}. Note that clients will send the same SCTs and
chains to a server multiple times with the assumption that any
man-in-the-middle attack eventually will cease, and an honest server
will eventually receive collected malicious SCTs and certificate
chains.

HTTPS servers store SCTs and certificate chains received from clients,
as described in {{feedback-srvop}}. They later share them with CT
auditors by either posting them to auditors or making them available
via a well-known URL. This is described in {{feedback-srvaud}}.

### SCT Feedback data format {#feedback-dataformat}

The data shared between HTTPS clients and servers, as well as between
HTTPS servers and CT auditors, is a JSON array {{RFC7159}}. Each item
in the array is a JSON object containing at least the first of the
following members:

- "x509_chain" : An array of PEM-encoded X.509 certificates. The first
  element is the end-entity certificate, the second certifies the
  first and so on. The "x509_chain" member is mandatory to include.

- "sct_data_v1" : An array of base64 encoded
  "SignedCertificateTimestampList"s as defined in {{RFC-6962}} section
  3.3. The "sct_data_v1" member is optional.

- "sct_data_v2" : An array of base64 encoded "TransItem" structures of
  type "x509_sct_v2" or "precert_sct_v2" as defined in {{6962-bis-27}}
  section 4.8. The "sct_data_v2" member is optional.

We will refer to this object as 'sct\_feedback'.

The x509\_chain element always contains a full chain from a leaf
certificate to a self-signed trust anchor.

See {{feedback-clisrv}} for details on what the sct\_data element
contains as well as more details about the x509\_chain element.

### HTTPS client to server {#feedback-clisrv}

When an HTTPS client connects to an HTTPS server, the client receives
a set of SCTs as part of the TLS handshake. SCTs are included in the
TLS handshake using one or more of the three mechanisms described in
{{RFC-6962-BIS-09}} section 3.4 -- in the server certificate, in a TLS
extension, or in an OCSP extension. The client MUST discard SCTs that
are not signed by a log known to the client and SHOULD store the
remaining SCTs together with a locally constructed certificate chain
which is trusted (i.e., terminated in a pre-loaded or locally installed
Trust Anchor) in an sct\_feedback object or equivalent data structure
for later use in SCT Feedback.

The SCTs stored on the client MUST be keyed by the exact domain name
the client contacted. They MUST NOT be sent to the well-known URI of
any domain not matching the original domain (e.g., if the original
domain is sub.example.com they must not be sent to sub.sub.example.com
or to example.com.) In particular, they MUST NOT be sent to the
well-known URI of any Subject Alternate Names specified in the
certificate. In the case of certificates that validate multiple domain
names, after visiting a second domain name specified in the 
certificate, the same SCT is expected to be stored once under each
domain name's key. If Connection Reuse as defined in {{RFC7540}} is
available, reusing an existing connection to sub.example.com to send
data to sub.sub.example.com is permitted.

Not following these constraints would increase the risk for two types
of privacy breaches. First, the HTTPS server receiving the SCT would
learn about other sites visited by the HTTPS client. Second, auditors
receiving SCTs from the HTTPS server would learn information about
other HTTPS servers visited by its clients.

If the client later again connects to the same HTTPS server, it again
receives a set of SCTs and calculates a certificate chain, and again
creates an sct\_feedback or similar object. If this object does not
exactly match an existing object in the store, then the client MUST
add this new object to the store, associated with the exact domain
name contacted, as described above. An exact comparison is needed to
ensure that attacks involving alternate chains are detected. An
example of such an attack is described in
{{dual-ca-compromise-attack}}. However, at least one optimization is
safe and MAY be performed: If the certificate chain exactly matches an
existing certificate chain, the client MAY store the union of the SCTs
from the two objects in the first (existing) object.

If the client does connect to the same HTTPS server a subsequent time,
it MUST send to the server sct\_feedback objects in the store that are
associated with that domain name. However, it is not necessary to send
an sct\_feedback object constructed from the current TLS session, and
if the client does so, it MUST NOT be marked as sent in any internal
tracking done by the client.

Refer to {{pooling-policy-recommendations}} for recommendations for
implementation.

Because SCTs can be used as a tracking mechanism (see
{{privacy-feedback}}), they deserve special treatment when they are
received from (and provided to) domains that are loaded as
subresources from an origin domain. Such domains are commonly called
'third party domains'. An HTTPS client SHOULD store SCT Feedback using
a 'double-keying' approach, which isolates third party domains by the
first party domain. This is described in {{double-keying}}. Gossip
would be performed normally for third party domains only when the user
revisits the first party domain. In lieu of 'double-keying', an HTTPS
client MAY treat SCT Feedback in the same manner it treats other
security mechanisms that can enable tracking (such as HSTS and HPKP.)

SCT Feedback is only performed when a user connects to a site via
intentional web browsing or normal third party resource inclusion.
It MUST NOT be performed automatically as part of some sort of
background process.

Finally, if the HTTPS client has configuration options for not sending
cookies to third parties, SCTs of third parties MUST be treated as
cookies with respect to this setting. This prevents third party
tracking through the use of SCTs/certificates, which would bypass the
cookie policy. For domains that are only loaded as third party
domains, the client may never perform SCT Feedback; however the client
may perform STH Pollination after fetching an inclusion proof, as
specified in {{sth-pollination}}.

SCTs and corresponding certificates are POSTed to the originating
HTTPS server at the well-known URL:

    https://<domain>/.well-known/ct-gossip/v1/sct-feedback

The data sent in the POST is defined in {{feedback-dataformat}}. This
data SHOULD be sent in an already-established TLS session. This makes
it hard for an attacker to disrupt SCT Feedback without also
disturbing ordinary secure browsing (https://). This is discussed more
in {{blocking-policy-frustrating}}.

The HTTPS server SHOULD respond with an HTTP 200 response code and an
empty body if it was able to process the request. An HTTPS client
which receives any other response SHOULD consider it an error.

Some clients have trust anchors or logs that are locally added
(e.g., by an administrator or by the user themselves). These additions
are potentially privacy-sensitive because they can carry information
about the specific configuration, computer, or user.

Certificates validated by locally added trust anchors will commonly
have no SCTs associated with them, so in this case no action is needed
with respect to CT Gossip. SCTs issued by locally added logs MUST NOT
be reported via SCT Feedback.

If a certificate is validated by SCTs that are issued by publicly
trusted logs, but chains to a local trust anchor, the client MAY
perform SCT Feedback for this SCT and certificate chain bundle. If it
does so, the client MUST include the full chain of certificates
chaining to the local trust anchor in the x509\_chain
array. Performing SCT Feedback in this scenario may be advantageous
for the broader internet and CT ecosystem, but may also disclose
information about the client. If the client elects to omit SCT
Feedback, it can choose to perform STH Pollination after fetching an
inclusion proof, as specified in {{sth-pollination}}.

We require the client to send the full chain (or nothing at all) for
two reasons. Firstly, it simplifies the operation on the server if
there are not two code paths. Secondly, omitting the chain does not
actually preserve user privacy. The Issuer field in the certificate
describes the signing certificate. And if the certificate is being
submitted at all, it means the certificate is logged, and has
SCTs. This means that the Issuer can be queried and obtained from the
log, so omitting the signing certificate from the client's submission
does not actually help user privacy.

### HTTPS server operation {#feedback-srvop}

HTTPS servers can be configured (or omit configuration), resulting in,
broadly, two modes of operation. In the simpler mode, the server will
only track leaf certificates and SCTs applicable to those leaf
certificates. In the more complex mode, the server will confirm the
client's chain validation and store the certificate chain. The latter
mode requires more configuration, but is necessary to prevent denial
of service (DoS) attacks on the server's storage space.

In the simple mode of operation, upon receiving a submission at the
sct-feedback well-known URL, an HTTPS server will perform a set of
operations, checking on each sct\_feedback object before storing it:

  1. the HTTPS server MAY modify the sct\_feedback object, and discard
     all items in the x509\_chain array except the first item (which
     is the end-entity certificate)

  2. if a bit-wise compare of the sct\_feedback object matches one
     already in the store, this sct\_feedback object SHOULD be
     discarded

  3. if the leaf cert is not for a domain for which the server is
     authoritative, the SCT MUST be discarded

  4. if an SCT in the sct\_data array can't be verified to be a valid
     SCT for the accompanying leaf cert, and issued by a known log,
     the individual SCT SHOULD be discarded

The modification in step number 1 is necessary to prevent a malicious
client from exhausting the server's storage space. A client can
generate their own issuing certificate authorities, and create an
arbitrary number of chains that terminate in an end-entity certificate
with an existing SCT. By discarding all but the end-entity
certificate, we prevent a simple HTTPS server from storing this
data. Note that operation in this mode will not prevent the attack
described in {{dual-ca-compromise-attack}}. Skipping this step
requires additional configuration as described below.

The check in step 2 is for detecting duplicates and minimizing
processing and storage by the server. As on the client, an exact
comparison is needed to ensure that attacks involving alternate chains
are detected. Again, at least one optimization is safe and MAY be
performed. If the certificate chain exactly matches an existing
certificate chain, the server MAY store the union of the SCTs from the
two objects in the first (existing) object. If the validity check on
any of the SCTs fails, the server SHOULD NOT store the union of the
SCTs.

The check in step 3 is to help malfunctioning clients from exposing
which sites they visit. It additionally helps prevent DoS attacks on
the server.

The check in step 4 is to prevent DoS attacks where an adversary fills
up the store prior to attacking a client (thus preventing the client's
feedback from being recorded), or an attack where an adversary simply
attempts to fill up server's storage space.

The above describes the simpler mode of operation. In the more
advanced server mode, the server will detect the attack described in
{{dual-ca-compromise-attack}}. In this configuration the server will
not modify the sct\_feedback object prior to performing checks 2, 3,
and 4. Instead, to prevent a malicious client from filling the 
server's data store, the HTTPS server SHOULD perform an additional
check in the more advanced mode:

  5. if the x509\_chain consists of an invalid certificate chain, or
  the culminating trust anchor is not recognized by the server, the
  server SHOULD modify the sct\_feedback object, discarding all items
  in the x509\_chain array except the first item

The HTTPS server MAY choose to omit checks 4 or 5. This will place the
server at risk of having its data store filled up by invalid data, but
can also allow a server to identify interesting certificate or
certificate chains that omit valid SCTs, or do not chain to a trusted
root. This information may enable an HTTPS server operator to detect
attacks or unusual behavior of Certificate Authorities even outside
the Certificate Transparency ecosystem.

### HTTPS server to auditors {#feedback-srvaud}

HTTPS servers receiving SCTs from clients SHOULD share SCTs and
certificate chains with CT auditors by either serving them on the
well-known URL:

    https://<domain>/.well-known/ct-gossip/v1/collected-sct-feedback

or by HTTPS POSTing them to a set of preconfigured auditors. This
allows an HTTPS server to choose between an active push model or a
passive pull model.

The data received in a GET of the well-known URL or sent in the POST
is defined in {{feedback-dataformat}} with the following difference:
The x509\_chain element may contain only he end-entity certificate, as
described below.

HTTPS servers SHOULD share all sct\_feedback objects they see that
pass the checks in {{feedback-srvop}}. If this is an infeasible amount
of data, the server MAY choose to expire submissions according to an
undefined policy. Suggestions for such a policy can be found in
{{pooling-policy-recommendations}}.

HTTPS servers MUST NOT share any other data that they may learn from
the submission of SCT Feedback by HTTPS clients, like the HTTPS client
IP address or the time of submission.

As described above, HTTPS servers can be configured (or omit
configuration), resulting in two modes of operation. In one mode, the
x509\_chain array will contain a full certificate chain. This chain
may terminate in a trust anchor the auditor may recognize, or it may
not. (One scenario where this could occur is if the client submitted a
chain terminating in a locally added trust anchor, and the server kept
this chain.) In the other mode, the x509\_chain array will consist of
only a single element, which is the end-entity certificate.

Auditors SHOULD provide the following URL accepting HTTPS POSTing of
SCT feedback data:

    https://<auditor>/ct-gossip/v1/sct-feedback

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
share STHs between HTTPS clients and CT auditors while still
preserving the privacy of the end user. The sharing of STHs contribute
to the overall goal of detecting misbehaving logs by providing CT
auditors with STHs from many vantage points, making it possible to
detect logs that are presenting inconsistent views.

HTTPS servers supporting the protocol act as STH pools. HTTPS clients
and CT auditors in the possession of STHs can pollinate STH pools by
sending STHs to them, and retrieving new STHs to send to other STH
pools. CT auditors can improve the value of their auditing by
retrieving STHs from pools.

HTTPS clients send STHs to HTTPS servers by POSTing them to the
well-known URL:

    https://<domain>/.well-known/ct-gossip/v1/sth-pollination

The data sent in the POST is defined in
{{sth-pollination-dataformat}}. This data SHOULD be sent in an already
established TLS session. This makes it hard for an attacker to disrupt
STH gossiping without also disturbing ordinary secure browsing
(https://). This is discussed more in {{blocking-policy-frustrating}}.

On a successful connection to an HTTPS server implementing STH
Pollination, the response code will be 200, and the response body is
application/json, containing zero or more STHs in the same format, as
described in {{sth-pollination-dataformat}}.

An HTTPS client may acquire STHs by several methods:

- in replies to pollination POSTs;
- asking logs that it recognizes for the current STH, either directly
  (v2/get-sth) or indirectly (for example over DNS)
- resolving an SCT and certificate to an STH via an inclusion proof
- resolving one STH to another via a consistency proof

HTTPS clients (that have STHs) and CT auditors SHOULD pollinate STH
pools with STHs. Which STHs to send and how often pollination should
happen is regarded as undefined policy with the exception of privacy
concerns explained below. Suggestions for the policy can be found in
{{pooling-policy-recommendations}}.

An HTTPS client could be tracked by giving it a unique or rare STH.
To address this concern, we place restrictions on different components
of the system to ensure an STH will not be rare.

- HTTPS clients silently ignore STHs from logs with an STH issuance
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

When multiplied by the number of logs from which a client accepts
STHs, this number of unique STHs grow and the negative privacy
implications grow with it. It's important that this is taken into
account when logs are chosen for default settings in HTTPS
clients. This concern is discussed upon in
{{privacy-sth-interaction}}.

A log may cease operation, in which case there will soon be no STH
within the validity window. Clients SHOULD perform all three methods
of gossip about a log that has ceased operation since it is possible
the log was still compromised and gossip can detect that. STH
Pollination is the one mechanism where a client must know about a log
shutdown. A client which does not know about a log shutdown MUST NOT
attempt any heuristic to detect a shutdown. Instead the client MUST be
informed about the shutdown from a verifiable source (e.g., a software
update), and be provided the final STH issued by the log. The client
SHOULD resolve SCTs and STHs to this final STH. If an SCT or STH
cannot be resolved to the final STH, clients SHOULD follow the
requirements and recommendations set forth in
{{blocking-policy-response}}.

### HTTPS Clients and Proof Fetching {#clients-proof-fetching}

There are two types of proofs a client may retrieve; inclusion proofs
and consistency proofs.

An HTTPS client will retrieve SCTs together with certificate chains
from an HTTPS server. Using the timestamp in the SCT together with the
end-entity certificate and the issuer key hash, it can obtain an
inclusion proof to an STH in order to verify the promise made by the
SCT.

An HTTPS client will have STHs from performing STH Pollination, and
may obtain a consistency proof to a more recent STH.

An HTTPS client may also receive an SCT bundled with an inclusion
proof to a historical STH via an unspecified future mechanism. Because
this historical STH is considered personally identifiable information
per above, the client needs to obtain a consistency proof to a more
recent STH.

A client SHOULD attempt proof fetching. A client MAY do network probing
to determine if proof fetching may succeed, and if it learns that it
does not, SHOULD periodically re-probe (especially after network
change, if it is aware of these events.) If it does succeed, queued
events can be processed.

A client MUST NOT perform proof fetching for any SCTs or STHs issued
by a locally added log. A client MAY fetch an inclusion proof for an
SCT (issued by a pre-loaded log) that validates a certificate
chaining to a locally added trust anchor.

If a client requested either proof directly from a log or auditor, it
would reveal the client's browsing habits to a third party. To
mitigate this risk, an HTTPS client MUST retrieve the proof in a
manner that disguises the client.

Depending on the client's DNS provider, DNS may provide an appropriate
intermediate layer that obfuscates the linkability between the user of
the client and the request for inclusion (while at the same time
providing a caching layer for oft-requested inclusion proofs). See
{{draft-ct-over-dns}} for an example of how this can be done.

Anonymity networks such as Tor also present a mechanism for a client
to anonymously retrieve a proof from an auditor or log.

Even when using a privacy-preserving layer between the client and the
log, certain observations may be made about an anonymous client or
general user behavior depending on how proofs are fetched. For
example, if a client fetched all outstanding proofs at once, a log
would know that SCTs or STHs received around the same time are more
likely to come from a particular client. This could potentially go so
far as correlation of activity at different times to a single
client. In aggregate the data could reveal what sites are commonly
visited together. HTTPS clients SHOULD use a strategy of proof
fetching that attempts to obfuscate these patterns. A suggestion of
such a policy can be found in {{proof-fetching-recommendations}}.

Resolving either SCTs and STHs may result in errors. These errors may
be routine downtime or other transient errors, or they may be
indicative of an attack. Clients SHOULD follow the requirements and
recommendations set forth in {{blocking-policy-response}} when
handling these errors in order to give the CT ecosystem the greatest
chance of detecting and responding to a compromise.

### STH Pollination without Proof Fetching

An HTTPS client MAY participate in STH Pollination without fetching
proofs. In this situation, the client receives STHs from a server,
applies the same validation logic to them (signed by a known log,
within the validity window) and will later pass them to another HTTPS
server.

When operating in this fashion, the HTTPS client is promoting gossip
for Certificate Transparency, but derives no direct benefit itself. In
comparison, a client which resolves SCTs or historical STHs to recent
STHs and pollinates them is assured that if it was attacked, there is
a probability that the ecosystem will detect and respond to the attack
(by distrusting the log).

### Auditor Action

CT auditors participate in STH pollination by retrieving STHs from
HTTPS servers. They verify that the STH is valid by checking the
signature, and requesting a consistency proof from the STH to the most
recent STH.

After retrieving the consistency proof to the most recent STH, they
SHOULD pollinate this new STH among participating HTTPS servers. In
this way, as STHs "age out" and are no longer fresh, their "lineage"
continues to be tracked in the system.

### STH Pollination data format {#sth-pollination-dataformat}

The data sent from HTTPS clients and CT auditors to HTTPS servers is a
JSON object {{RFC7159}} with one or both of the following two members:

- "v1" : array of 0 or more objects each containing an STH as returned
  from ct/v1/get-sth, see {{RFC6962}} section 4.3

- "v2" : array of 0 or more objects each containing an STH as returned
  from ct/v2/get-sth, see {{6962-bis-27}} section 5.2

Note that all STHs MUST be fresh as defined in {{sth-pollination}}.

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
privacy perspective. The HTTPS client may also do its own auditing and
might additionally share SCTs and STHs with the trusted party to
contribute to herd immunity. Here, the ordinary {{RFC-6962-BIS-09}}
protocol is sufficient for the client to do the auditing while SCT
Feedback and STH Pollination can be used in whole or in parts for the
gossip part.

Another well established trusted party arrangement on the internet
today is the relation between internet users and their providers of
DNS resolver services. DNS resolvers are typically provided by the
internet service provider (ISP) used, which by the nature of name
resolving already know a great deal about which sites their users
visit. As mentioned in {{clients-proof-fetching}}, in order for HTTPS
clients to be able to retrieve proofs in a privacy preserving manner,
logs could expose a DNS interface in addition to the ordinary HTTPS
interface. A specification of such a protocol can be found in
{{draft-ct-over-dns}}.


### Trusted Auditor data format

Trusted Auditors expose a REST API at the fixed URI:

    https://<auditor>/ct-gossip/v1/trusted-auditor

Submissions are made by sending an HTTPS POST request, with the body of
the POST in a JSON object. Upon successful receipt the Trusted Auditor
returns 200 OK.

The JSON object consists of two top-level keys: 'sct\_feedback' and
'sths'. The 'sct\_feedback' value is an array of JSON objects as
defined in {{feedback-dataformat}}. The 'sths' value is an array of
STHs as defined in {{sth-pollination-dataformat}}.

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

The use of three distinct methods for auditing logs may seem
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
- Establish a "push" mechanism for POSTing SCTs to CT auditors

These configuration needs, and the simple fact that it would require
some deployment of software, means that some percentage of HTTPS
servers will not deploy SCT Feedback.

If SCT Feedback was the only mechanism in the ecosystem, any server
that did not implement the feature would open itself and its users to
attack without any possibility of detection.

A webserver not deploying SCT Feedback (or an alternative method
providing equivalent functionality) may never learn that it was a
target of an attack by a malicious log, as described in
{{actively-malicious-log}}, although the presence of an attack by the
log could be learned through STH Pollination. Additionally, users who
wish to have the strongest measure of privacy protection (by disabling
STH Pollination Proof Fetching and forgoing a Trusted Auditor) could
be attacked without risk of detection.

## STH Pollination {#threemetheco-sth-pollination}

STH Pollination requires the cooperation of HTTPS clients, HTTPS
servers, and logs.

For a client to fully participate in STH Pollination, and have this
mechanism detect attacks against it, the client must have a way to
safely perform Proof Fetching in a privacy preserving manner. (The
client may pollinate STHs it receives without performing Proof
Fetching, but we do not consider this option in this section.)

HTTPS servers must deploy software (although, as in the case with SCT
Feedback this logic can be pre-provided) and commit some configurable
amount of disk space to the endeavor.

Logs (or a third party mirroring the logs) must provide access to
clients to query proofs in a privacy preserving manner, most likely
through DNS.

Unlike SCT Feedback, the STH Pollination mechanism is not hampered if
only a minority of HTTPS servers deploy it. However, it makes an
assumption that an HTTPS client performs Proof Fetching (such as the
DNS mechanism discussed). Unfortunately, any manner that is anonymous
for some (such as clients which use shared DNS services such as a
large ISP), may not be anonymous for others.

For instance, DNS requests expose a considerable amount of sensitive
information (including what data is already present in the cache) in
plaintext over the network. For this reason, some percentage of HTTPS
clients may choose to not enable the Proof Fetching component of STH
Pollination. (Although they can still request and send STHs among
participating HTTPS servers, even when this affords them no direct
benefit.)

If STH Pollination was the only mechanism deployed, users that disable
it would be able to be attacked without risk of detection.

If STH Pollination (or an alternative method providing equivalent
functionality) was not deployed, HTTPS clients visiting HTTPS Servers
which did not deploy SCT Feedback could be attacked without risk of
detection.

## Trusted Auditor Relationship

The Trusted Auditor Relationship is expected to be the rarest gossip
mechanism, as an HTTPS client is providing an unadulterated report of
its browsing history to a third party. While there are valid and
common reasons for doing so, there is no appropriate way to enter into
this relationship without retrieving informed consent from the user.

However, the Trusted Auditor Relationship mechanism still provides
value to a class of HTTPS clients. For example, web crawlers have no
concept of a "user" and no expectation of privacy. Organizations
already performing network auditing for anomalies or attacks can run
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

Assuming no other log consistency measures exist, clients who perform
only a subset of the mechanisms described in this document are exposed
to the following vulnerabilities:

HTTPS clients can be attacked without risk of detection if they do not
participate in any of the three mechanisms.

HTTPS clients are afforded the greatest chance of detecting an attack
when they either participate in both SCT Feedback and STH Pollination
with Proof Fetching or if they have a Trusted Auditor relationship.
(Participating in SCT Feedback is the only way specified in this
document to prevent a malicious log from refusing to ever resolve
an SCT to an STH, as put forward in {{actively-malicious-log}}).
Additionally, participating in SCT Feedback enables an HTTPS client
to assist in detecting the exact target of an attack.

HTTPS servers that omit SCT Feedback enable malicious logs to carry
out attacks without risk of detection. If these servers are targeted
specifically, even if the attack is detected, without SCT Feedback
they may never learn that they were specifically targeted. HTTPS
servers without SCT Feedback do gain some measure of herd immunity,
but only because their clients participate in STH Pollination (with
Proof Fetching) or have a Trusted Auditor Relationship.

When HTTPS servers omit SCT feedback, it allows their users to be
attacked without detection by a malicious log; the vulnerable users
are those who do not have a Trusted Auditor relationship.

# Security considerations

## Attacks by actively malicious logs {#actively-malicious-log}

One of the most powerful attacks possible in the CT ecosystem is a
trusted log that has actively decided to be malicious. It can carry
out an attack in at least two ways:

In the first attack, the log can present a split view of the log for
all time. This attack can be detected by CT auditors, but a naive
auditor implementation may fail to do so. The simplest, least
efficient way to detect the attack is to mirror the entire log and
assert inclusion of every peice of data. If an auditor does not mirror
the log, one way to detect this attack is to resolve each view
of the log to the most recent STHs available and then force the log to
present a consistency proof. (Which it cannot.) We highly recommend
auditors plan for this attack scenario and ensure it will be detected.

In the second attack, the log can sign an SCT, and refuse to ever
include the certificate that the SCT refers to in the
tree. (Alternately, it can include it in a branch of the tree and
issue an STH, but then abandon that branch.) Whenever someone requests
an inclusion proof for that SCT (or a consistency proof from that
STH), the log would respond with an error, and a client may simply
regard the response as a transient error. This attack can be detected
using SCT Feedback, or an Auditor of Last Resort, as presented in
{{blocking-policy-response}}.

Both of these attack variants can be detected by CT auditors who have
obtained an STH of an 'abnormal' view of the log. However, they may not
be able to link the STH to any particular SCT or Certificate. This
means that while the log misbehavior was successfully detected, the
target of the attack was not identified. To assertively identify the
target(s) of the attack, SCT Feedback is necessary.

## Dual-CA Compromise {#dual-ca-compromise}

{{dual-ca-compromise-attack}} describes an attack possible by an
adversary who compromises two Certificate Authorities and a Log. This
attack is difficult to defend against in the CT ecosystem, and
{{dual-ca-compromise-attack}} describes a few approaches to doing
so. We note that Gossip is not intended to defend against this attack,
but can in certain modes.

Defending against the Dual-CA Compromise attack requires SCT Feedback,
and explicitly requires the server to save full certificate chains
(described in {{feedback-srvop}} as the 'complex' configuration.) After
CT auditors receive the full certificate chains from servers, they MAY
compare the chain built by clients to the chain supplied by the log. If
the chains differ significantly, the auditor SHOULD raise a concern. A
method of determining if chains differ significantly is by asserting
that one chain is not a subset of the other and that the roots of the
chains are different.

## Censorship/Blocking considerations

We assume a network attacker who is able to fully control the client's
internet connection for some period of time, including selectively
blocking requests to certain hosts and truncating TLS connections
based on information observed or guessed about client behavior. In
order to successfully detect log misbehavior, the gossip mechanisms
must still work even in these conditions.

There are several gossip connections that can be blocked:

  1. Clients sending SCTs to servers in SCT Feedback

  2. Servers sending SCTs to auditors in SCT Feedback (server push
     mechanism)

  3. Servers making SCTs available to auditors (auditor pull
     mechanism)

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
data with the recipient, when it has not. However, in both scenarios
(3 and 6), the server cannot distinguish the client as a cooperating
member of the CT ecosystem or as an attacker performing a Sybil
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

## Flushing Attacks

A flushing attack is an attempt by an adversary to flush a particular
piece of data from a pool. In the CT Gossip ecosystem, an attacker may
have performed an attack and left evidence of a compromised log on a
client or server. They would be interested in flushing that data, i.e.
tricking the target into gossiping or pollinating the incriminating
evidence with only attacker-controlled clients or servers with the
hope they trick the target into deleting it.

Flushing attacks may be defended against differently depending on the
entity (HTTPS client or HTTPS server) and record (STHs or SCTs with
Certificate Chains).

### STHs

For both HTTPS clients and HTTPS servers, STHs within the validity
window SHOULD NOT be deleted. An attacker cannot flush an item from
the cache if it is never removed so flushing attacks are completely
mitigated.

The required disk space for all STHs within the validity window is 336
STHs per log that is trusted. If 20 logs are trusted, and each STH
takes 1 Kilobytes, this is 6.56 Megabytes.

Note that it is important that implementors do not calculate the exact
size of cache expected -- if an attack does occur, a small number of
additional, fraudulent STHs will enter into the cache. These STHs will
be in addition to the expected set, and will be evidence of the attack.
Flooding the cache will not work, as an attacker would have to include
fraudulent STHs in the flood.

If an HTTPS client or HTTPS server is operating in a constrained
environment and cannot devote enough storage space to hold all STHs
within the validity window it is recommended to use the below Deletion
Algorithm in section {{deletion-algorithm}} to make it more difficult
for the attacker to perform a flushing attack.

### SCTs & Certificate Chains on HTTPS Servers

An HTTPS server will only accept SCTs and Certificate Chains for
domains it is authoritative for. Therefore the storage space needed is
bound by the number of logs it accepts, multiplied by the number of
domains it is authoritative for, multiplied by the number of
certificates issued for those domains.

Imagine a server authoritative for 10,000 domains, and each domain has
3 certificate chains, and 10 SCTs. A certificate chain is 5 Kilobytes
in size and an SCT 1 Kilobyte. This yields 732 Megabytes.

This data can be large, but it is calculable. Web properties with more
certificates and domains are more likely to be able to handle the
increased storage need, while small web properties will not seen an
undue burden. Therefore HTTPS servers SHOULD NOT delete SCTs or
Certificate Chains. This completely mitigates flushing attacks.

Again, note that it is important that implementors do not calculate
the exact size of cache expected -- if an attack does occur, the new
SCT(s) and Certificate Chain(s) will enter into the cache. This data
will be in addition to the expected set, and will be evidence of the
attack.

If an HTTPS server is operating in a constrained environment and
cannot devote enough storage space to hold all SCTs and Certificate
Chains it is authoritative for it is recommended to configure the SCT
Feedback mechanism to allow only certain certificates that are known
to be valid. These chains and SCTs can then be discarded without being
stored or subsequently provided to any clients or auditors. If the
allowlist is not sufficient, the below Deletion Algorithm in
{{deletion-algorithm}} is recommended to make it more difficult for
the attacker to perform a flushing attack.

### SCTs & Certificate Chains on HTTPS Clients

HTTPS clients will accumulate SCTs and Certificate Chains without
bound. It is expected they will choose a particular cache size and
delete entries when the cache size meets its limit. This does not
mitigate flushing attacks, and such an attack is documented in
{{gossip-mixing}}.

The below Deletion Algorithm {{deletion-algorithm}} is recommended to
make it more difficult for the attacker to perform a flushing attack.

## Privacy considerations

CT Gossip deals with HTTPS clients which are trying to share
indicators that correspond to their browsing history. The most
sensitive relationships in the CT ecosystem are the relationships
between HTTPS clients and HTTPS servers. Client-server relationships
can be aggregated into a network graph with potentially serious
implications for correlative de-anonymization of clients and
relationship-mapping or clustering of servers or of clients.

There are, however, certain clients that do not require privacy
protection. Examples of these clients are web crawlers or robots. But
even in this case, the method by which these clients crawl the web may
in fact be considered sensitive information. In general, it is better
to err on the side of safety, and not assume a client is okay with
giving up its privacy.

### Privacy and SCTs {#privacy-SCT}

An SCT contains information that links it to a particular web
site. Because the client-server relationship is sensitive, gossip
between clients and servers about unrelated SCTs is risky. Therefore,
a client with an SCT for a given server SHOULD NOT transmit that
information in any other than the following two channels: to the
server associated with the SCT itself (via a TLS connection with a
certificate identifying the Domain Name of the web site with a Host
header specifying the domain name); or to a Trusted Auditor, if one
exists.

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
requirement that logs must use a deterministic signature scheme when
signing SCTs ({{RFC-6962-BIS-09}} Section 2.1.4). A log signing using
RSA is not required to use a deterministic signature scheme.

Since logs are allowed to issue a new SCT for a certificate already
present in the log, mandating deterministic signatures does not stop
this fingerprinting attack altogether. It does make the attack harder
to pull off without being detected though.

There is another similar fingerprinting attack where an HTTPS server
tracks a client by using a unique certificate or a variation of cert
chains. The risk for this attack is accepted on the same grounds as
the unique SCT attack described above.

### Privacy for HTTPS clients performing STH Proof Fetching

An HTTPS client performing Proof Fetching SHOULD NOT request proofs
from a CT log that it doesn't accept SCTs from. An HTTPS client SHOULD
regularly request an STH from all logs it is willing to accept, even
if it has seen no SCTs from that log.

The time between two polls for new STH's SHOULD NOT be significantly
shorter than the MMD of the polled log divided by its STH Frequency
Count ({{RFC-6962-BIS-09}} section 5.1).

The actual mechanism by which Proof Fetching is done carries
considerable privacy concerns. Although out of scope for the document,
DNS is a mechanism currently discussed. DNS exposes data in plaintext
over the network (including what sites the user is visiting and what
sites they have previously visited) and may not be suitable for some.

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
cross-origin. If a log (or HTTPS server cooperating with a log)
provides a unique STH to a client, the targeted client will be the
only client pollinating that STH cross-origin.

It is mitigated partially because the log is limited in the number of
STHs it can issue. It must 'save' one of its STHs each MMD to perform
the attack. A log violating its STH Frequency Count
({{RFC-6962-BIS-27}} section 4.1) can be identified as non-compliant
by CT auditors following the procedure described in
{{RFC-6962-BIS-27}} section 8.3.

### Privacy in STH Interaction {#privacy-sth-interaction}

An HTTPS client may pollinate any STH within the last 14 days. An
HTTPS client may also pollinate an STH for any log that it knows
about. When a client pollinates STHs to a server, it will release more
than one STH at a time. It is unclear if a server may 'prime' a client
and be able to reliably detect the client at a later time.

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

Clients which wish to contact a CT auditor without associating their
identities with their SCTs may wish to use an anonymizing network like
Tor to submit SCT Feedback to the auditor. Auditors SHOULD accept SCT
Feedback that arrives over such anonymizing networks.

Clients sending feedback to an auditor may prefer to reduce the
temporal granularity of the history exposure to the auditor by caching
and delaying their SCT Feedback reports. This is elaborated upon in
{{pooling-policy-recommendations}}. This strategy is only as effective
as the granularity of the timestamps embedded in the SCTs and STHs.

### HTTPS Clients as Auditors

Some HTTPS clients may choose to act as CT auditors themselves. A Client
taking on this role needs to consider the following:

- an Auditing HTTPS client potentially exposes its history to the logs
  that they query. Querying the log through a cache or a proxy with
  many other users may avoid this exposure, but may expose information
  to the cache or proxy, in the same way that a non-Auditing HTTPS
  Client exposes information to a Trusted Auditor.

- an effective CT auditor needs a strategy about what to do in the
  event that it discovers misbehavior from a log. Misbehavior from a
  log involves the log being unable to provide either (a) a
  consistency proof between two valid STHs or (b) an inclusion proof
  for a certificate to an STH any time after the log's MMD has elapsed
  from the issuance of the SCT. The log's inability to provide either
  proof will not be externally cryptographically-verifiable, as it may
  be indistinguishable from a network error.

# Policy Recommendations

This section is intended as suggestions to implementors of HTTPS
Clients, HTTPS servers, and CT auditors. It is not a requirement for
technique of implementation, so long as the privacy considerations
established above are obeyed.

## Blocking Recommendations {#blocking-policy-recommendations}

### Frustrating blocking {#blocking-policy-frustrating}

When making gossip connections to HTTPS servers or Trusted Auditors,
it is desirable to minimize the plaintext metadata in the connection
that can be used to identify the connection as a gossip connection and
therefore be of interest to block. Additionally, introducing some
randomness into client behavior may be important. We assume that the
adversary is able to inspect the behavior of the HTTPS client and
understand how it makes gossip connections.

As an example, if a client, after establishing a TLS connection (and
receiving an SCT, but not making its own HTTP request yet),
immediately opens a second TLS connection for the purpose of gossip,
the adversary can reliably block this second connection to block
gossip without affecting normal browsing. For this reason it is
recommended to run the gossip protocols over an existing connection to
the server, making use of connection multiplexing such as HTTP
Keep-Alive or SPDY.

Truncation is also a concern. If a client always establishes a TLS
connection, makes a request, receives a response, and then always
attempts a gossip communication immediately following the first
response, truncation will allow an attacker to block gossip reliably.

For these reasons, we recommend that, if at all possible, clients
SHOULD send gossip data in an already established TLS session. This
can be done through the use of HTTP Pipelining, SPDY, or HTTP/2.

### Responding to possible blocking {#blocking-policy-response}

In some circumstances a client may have a piece of data that they have
attempted to share (via SCT Feedback or STH Pollination), but have
been unable to do so: with every attempt they receive an error. These
situations are:

  1. The client has an SCT and a certificate, and attempts to retrieve
     an inclusion proof -- but receives an error on every attempt.

  2. The client has an STH, and attempts to resolve it to a newer STH
     via a consistency proof -- but receives an error on every
     attempt.

  3. The client has attempted to share an SCT and constructed
     certificate via SCT Feedback -- but receives an error on every
     attempt.

  4. The client has attempted to share an STH via STH Pollination --
     but receives an error on every attempt.

  5. The client has attempted to share a specific piece of data with a
     Trusted Auditor -- but receives an error on every attempt.

In the case of 1 or 2, it is conceivable that the reason for the
errors is that the log acted improperly, either through malicious
actions or compromise. A proof may not be able to be fetched because
it does not exist (and only errors or timeouts occur). One such
situation may arise because of an actively malicious log, as presented
in {{actively-malicious-log}}. This data is especially important to
share with the broader internet to detect this situation.

If an SCT has attempted to be resolved to an STH via an inclusion
proof multiple times, and each time has failed, this SCT might very
well be a compromising proof of an attack. However the client MUST NOT
share the data with any other third party (excepting a Trusted Auditor
should one exist).

If an STH has attempted to be resolved to a newer STH via a
consistency proof multiple times, and each time has failed, a client
MAY share the STH with an "Auditor of Last Resort" even if the STH in
question is no longer within the validity window. This auditor may be
pre-configured in the client, but the client SHOULD permit a user to
disable the functionality or change whom data is sent to. The Auditor
of Last Resort itself represents a point of failure and privacy
concerns, so if implemented, it SHOULD connect using public key
pinning and not consider an item delivered until it receives a
confirmation.

In the cases 3, 4, and 5, we assume that the webserver(s) or trusted
auditor in question is either experiencing an operational failure, or
being attacked. In both cases, a client SHOULD retain the data for
later submission (subject to Private Browsing or other
history-clearing actions taken by the user.) This is elaborated upon
more in {{pooling-policy-recommendations}}.

## Proof Fetching Recommendations {#proof-fetching-recommendations}

Proof fetching (both inclusion proofs and consistency proofs) SHOULD
be performed at random time intervals. If proof fetching occurred all
at once, in a flurry of activity, a log would know that SCTs or STHs
received around the same time are more likely to come from a
particular client. While proof fetching is required to be done in a
manner that attempts to be anonymous from the perspective of the log,
the correlation of activity to a single client would still reveal
patterns of user behavior we wish to keep confidential. These patterns
could be recognizable as a single user, or could reveal what sites are
commonly visited together in the aggregate.

## Record Distribution Recommendations {#pooling-policy-recommendations}

In several components of the CT Gossip ecosystem, the recommendation
is made that data from multiple sources be ingested, mixed, stored for
an indeterminate period of time, provided (multiple times) to a third
party, and eventually deleted. The instances of these recommendations
in this draft are:

- When a client receives SCTs during SCT Feedback, it should store the
  SCTs and Certificate Chain for some amount of time, provide some of
  them back to the server at some point, and may eventually remove
  them from its store

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
and each have options that may not be invoked. As one example, an
HTTPS client should not mix SCTs from server A with SCTs from server B
and release server B's SCTs to Server A. As another example, an HTTPS
server may choose to resolve STHs to a single more current STH via
proof fetching, but it is under no obligation to do so.

These requirements should be met, but the general problem of
aggregating multiple pieces of data, choosing when and how many to
release, and when to remove them is shared. This problem has
previously been considered in the case of Mix Networks and Remailers,
including papers such as {{trickle}}.

There are several concerns to be addressed in this area, outlined
below.

### Mixing Algorithm

When SCTs or STHs are recorded by a participant in CT Gossip and later
used, it is important that they are selected from the datastore in a
non-deterministic fashion.

This is most important for servers, as they can be queried for SCTs
and STHs anonymously. If the server used a predictable ordering
algorithm, an attacker could exploit the predictability to learn
information about a client. One such method would be by observing the
(encrypted) traffic to a server. When a client of interest connects,
the attacker makes a note. They observe more clients connecting, and
predicts at what point the client-of-interest's data will be
disclosed, and ensures that they query the server at that point.

Although most important for servers, random ordering is still strongly
recommended for clients and Trusted Auditors. The above attack can
still occur for these entities, although the circumstances are less
straightforward. For clients, an attacker could observe their
behavior, note when they receive an STH from a server, and use
javascript to cause a network connection at the correct time to force
a client to disclose the specific STH. Trusted Auditors are stewards
of sensitive client data. If an attacker had the ability to observe
the activities of a Trusted Auditor (perhaps by being a log, or
another auditor), they could perform the same attack -- noting the
disclosure of data from a client to the Trusted Auditor, and then
correlating a later disclosure from the Trusted Auditor as coming from
that client.

Random ordering can be ensured by several mechanisms. A datastore can
be shuffled, using a secure shuffling algorithm such as
Fisher-Yates. Alternately, a series of random indexes into the data
store can be selected (if a collision occurs, a new index is
selected.) A cryptographically secure random number generator must be
used in either case. If shuffling is performed, the datastore must be
marked 'dirty' upon item insertion, and at least one shuffle operation
occurs on a dirty datastore before data is retrieved from it for use.

### The Deletion Algorithm {#deletion-algorithm}

No entity in CT Gossip is required to delete records at any time,
except to respect user's wishes such as private browsing mode or
clearing history. However, it is likely that over time the accumulated
storage will grow in size and need to be pruned.

While deletion of data will occur, proof fetching can ensure that any
misbehavior from a log will still be detected, even after the direct
evidence from the attack is deleted. Proof fetching ensures that if a
log presents a split view for a client, they must maintain that split
view in perpetuity. An inclusion proof from an SCT to an STH does not
erase the evidence -- the new STH is evidence itself. A consistency
proof from that STH to a new one likewise -- the new STH is every bit
as incriminating as the first. (Client behavior in the situation where
an SCT or STH cannot be resolved is suggested in
{{blocking-policy-response}}.) Because of this property, we recommend
that if a client is performing proof fetching, that they make every
effort to not delete data until it has been successfully resolved to a
new STH via a proof.

When it is time to delete a record, it can be done in a way that makes
it more difficult for a successful flushing attack to to be performed.

  1. When the record cache has reached a certain size that is yet
     under the limit, aggressively perform proof fetching. This should
     resolve records to a small set of STHs that can be retained. Once
     a proof has been fetched, the record is safer to delete.

  2. If proof fetching has failed, or is disabled, begin by deleting
     SCTs and Certificate Chains that have been successfully reported.
     Deletion from this set of SCTs should be done at random. For a
     client, a submission is not counted as being reported unless it
     is sent over a connection using a different SCT, so the attacker
     is faced with a recursive problem. (For a server, this step does
     not apply.)

  3. Attempt to save any submissions that have failed proof fetching
     repeatedly, as these are the most likely to be indicative of an
     attack.

  4. Finally, if the above steps have been followed and have not
     succeeded in reducing the size sufficiently, records may be
     deleted at random.

Note that if proof fetching is disabled (which is expected although
not required for servers) -- the algorithm collapses down to 'delete
at random'.

The decision to delete records at random is intentional. Introducing
non-determinism in the decision is absolutely necessary to make it
more difficult for an adversary to know with certainty or high
confidence that the record has been successfully flushed from a
target.

## Concrete Recommendations

We present the following pseudocode as a concrete outline of our
policy recommendations.

Both suggestions presented are applicable to both clients and servers.
Servers may not perform proof fetching, in which case large portions
of the pseudocode are not applicable. But it should work in either
case.

Note that we use a function 'rand()' in the pseudocode, this function
is assumed to be a cryptographically secure pseudorandom 
number generator. Additionally, when N unique items are needed, they
are chosen at random by drawing a random index repeatedly until the N
unique items from an array have been chosen. Although simple, when the
array is N or near-N items in length this is inefficient. A secure
shuffle algorithm followed by selecting the first N items may be more
efficient, especially when N is large.

### STH Pollination {#recommendations-sth-pollination}

The STH class contains data pertaining specifically to the STH itself.

    class STH
    {
      uint16   proof_attempts
      uint16   proof_failure_count
      uint32   num_reports_to_thirdparty
      datetime timestamp
      byte[]   data
    }

The broader STH store itself would contain all the STHs known by an
entity participating in STH Pollination (either client or
server). This simplistic view of the class does not take into account
the complicated locking that would likely be required for a data
structure being accessed by multiple threads. Something to note about
this pseudocode is that it does not remove STHs once they have been
resolved to a newer STH. Doing so might make older STHs within the
validity window rarer and thus enable tracking.

    class STHStore
    {
      STH[] sth_list

      //  This function is run after receiving a set of STHs from
      //  a third party in response to a pollination submission
      def insert(STH[] new_sths) {
        foreach(new in new_sths) {
          if(this.sth_list.contains(new))
            continue
          this.sth_list.insert(new)
        }
      }

      //  This function is called to delete the given STH
      //  from the data store
      def delete_now(STH s) {
        this.sth_list.remove(s)
      }

      //  When it is time to perform STH Pollination, the HTTPS client
      //  calls this function to get a selection of STHs to send as
      //  feedback
      def get_pollination_selection() {
        if(len(this.sth_list) < MAX_STH_TO_GOSSIP)
          return this.sth_list
        else {
          indexes = set()
          modulus = len(this.sth_list)
          outdated_sths = 0
          while(len(indexes) + outdated_sths < MAX_STH_TO_GOSSIP) {
            r = randomInt() % modulus
            if(r not in indexes)
              // Ignore STHs that are past the validity window but not
              // yet removed.
              if(now() - this.sth_list[i].timestamp < TWO_WEEKS)
                outdated_sths++;
              else
                indexes.insert(r)
          }

          return_selection = []
          foreach(i in indexes) {
            return_selection.insert(this.sth_list[i])
          }
          return return_selection
        }
      }
    }

We also suggest a function that will be called periodically in the
background, iterating through the STH store, performing a cleaning
operation and queuing consistency proofs. This function can live as a
member functions of the STHStore class.

    //Just a suggestion:
    #define MIN_PROOF_FAILURES_CONSIDERED_SUSPICIOUS 3

    def clean_list() {
      foreach(sth in this.sth_list) {

        if(now() - sth.timestamp > TWO_WEEKS) {
          //STH is too old, we must remove it
          if(proof_fetching_enabled
             && auditor_of_last_resort_enabled
             && sth.proof_failure_count
                > MIN_PROOF_FAILURES_CONSIDERED_SUSPICIOUS) {
            queue_for_auditor_of_last_resort(sth,
                                            auditor_of_last_resort_callback)
          } else {
            delete_now(sth)
          }
        }


        else if(proof_fetching_enabled
                && now() - sth.timestamp > LOG_MMD
                && sth.proof_attempts != UINT16_MAX
                // Only fetch a proof is we have never received a proof
                // before. (This also avoids submitting something
                // already in the queue.)
                && sth.proof_attempts == sth.proof_failure_count) {
          sth.proof_attempts++
          queue_consistency_proof(sth, consistency_proof_callback)
        }
      }
    }

These functions also exist in the STHStore class.

    //  This function is called after successfully pollinating STHs
    //  to a third party. It is passed the STHs sent to the third
    //  party, which is the output of get_gossip_selection(), as well
    //  as the STHs received in the response.
    def successful_thirdparty_submission_callback(STH[] submitted_sth_list,
                                                  STH[] new_sths)
    {
      foreach(sth in submitted_sth_list) {
        sth.num_reports_to_thirdparty++
      }

      this.insert(new_sths);
    }


    //  Attempt auditor of last resort submissions until it succeeds
    def auditor_of_last_resort_callback(original_sth, error) {
      if(!error) {
        delete_now(original_sth)
      }
    }


    def consistency_proof_callback(consistency_proof, original_sth, error) {
      if(!error) {
        insert(consistency_proof.current_sth)
      } else {
        original_sth.proof_failure_count++
      }
    }

### SCT Feedback

The SCT class contains data pertaining specifically to an SCT itself.

    class SCT
    {
      uint16 proof_failure_count
      bool   has_been_resolved_to_sth
      bool   proof_outstanding
      byte[] data
    }

The SCT bundle will contain the trusted certificate chain the HTTPS
client built (chaining to a trusted root certificate.) It also
contains the list of associated SCTs, the exact domain it is
applicable to, and metadata pertaining to how often it has been
reported to the third party.

    class SCTBundle
    {
      X509[] certificate_chain
      SCT[]  sct_list
      string domain
      uint32 num_reports_to_thirdparty

      def equals(sct_bundle) {
        if(sct_bundle.domain != this.domain)
          return false
        if(sct_bundle.certificate_chain != this.certificate_chain)
          return false
        if(sct_bundle.sct_list != this.sct_list)
          return false

        return true
      }
      def approx_equals(sct_bundle) {
        if(sct_bundle.domain != this.domain)
          return false
        if(sct_bundle.certificate_chain != this.certificate_chain)
          return false

        return true
      }

      def insert_scts(sct[] sct_list) {
        this.sct_list.union(sct_list)
        this.num_reports_to_thirdparty = 0
      }

      def has_been_fully_resolved_to_sths() {
        foreach(s in this.sct_list) {
          if(!s.has_been_resolved_to_sth && !s.proof_outstanding)
            return false
        }
        return true
      }

      def max_proof_failures() {
        uint max = 0
        foreach(sct in this.sct_list) {
          if(sct.proof_failure_count > max)
            max = sct.proof_failure_count
        }
        return max
      }
    }

For each domain, we store a SCTDomainEntry that holds the SCTBundles
seen for that domain, as well as encapsulating some logic relating to
SCT Feedback for that particular domain.  In particular, this data
structure also contains the logic that handles domains not supporting
SCT Feedback. Its behavior is:

  1. When a user visits a domain, SCT Feedback is attempted for it. If
     it fails, it will retry after a month (configurable). If it
     succeeds, excellent. SCT Feedback data is still collected and
     stored even if SCT Feedback failed.

  2. After 3 month-long waits between failures, the domain will be
     marked as failing long-term. No SCT Feedback data will be stored
     beyond meta-data, but SCT Feedback will still be attempted after
     month-long waits

  3. If at any point in time, SCT Feedback succeeds, all failure
     counters are reset

  4. If a domain succeeds, but then begins failing, it must fail more
     than 90% of the time (configurable) and then the process begins
     at (2).

If a domain is visited infrequently (say, once every 7 months) then it
will be evicted from the cache and start all over again (according to
the suggestion values in the below pseudocode).

    //Suggestions:
    //  After concluding a domain doesn't support feedback, we try again
    //  after WAIT_BETWEEN_SCT_FEEDBACK_ATTEMPTS amount of time to see if
    //  they added support
    #define WAIT_BETWEEN_SCT_FEEDBACK_ATTEMPTS                     1 month

    //  If we've waited MIN_SCT_FEEDBACK_ATTEMPTS_BEFORE_OMITTING_STORAGE
    //  multiplied by WAIT_BETWEEN_SCT_FEEDBACK_ATTEMPTS amount of time, we
    //  still attempt SCT Feedback, but no longer bother storing any data
    //  until the domain supports SCT Feedback
    #define MIN_SCT_FEEDBACK_ATTEMPTS_BEFORE_OMITTING_STORAGE      3

    //  If this percentage of SCT Feedback attempts previously succeeded,
    //  we consider the domain as supporting feedback and is just having
    //  transient errors
    #define MIN_RATIO_FOR_SCT_FEEDBACK_TO_BE_WORKING               .10

    class SCTDomainEntry
    {
      //  This is the primary key of the object, the exact domain name it
      //  is valid for
      string   domain

      //  This is the last time the domain was contacted. For client
      //  operations it is updated whenever the client makes any request
      //  (not just feedback) to the domain. For server operations, it is
      //  updated whenever any client contacts the domain. Responsibility
      //  for updating lies OUTSIDE of the class
      public datetime last_contact_for_domain

      //  This is the last time SCT Feedback was attempted for the domain.
      //  It is updated whenever feedback is attempted - responsibility for
      //  updating lies OUTSIDE of the class
      //  This is not used when this algorithm runs on servers
      public datetime last_sct_feedback_attempt

      //  This is the number of times we have waited an
      //  WAIT_BETWEEN_SCT_FEEDBACK_ATTEMPTS amount of time, and still failed
      //  e.g., 10 months of failures
      //  This is not used when this algorithm runs on servers
      private uint16   num_feedback_loop_failures

      //  This is whether or not SCT Feedback has failed enough times that we
      //  should not bother storing data for it anymore. It is a small function
      //  used for illustrative purposes
      //  This is not used when this algorithm runs on servers
      private bool     sct_feedback_failing_longterm()
        { num_feedback_loop_failures >= MIN_SCT_FEEDBACK_ATTEMPTS_BEFORE_OMITTING_STORAGE }

      //  This is the number of SCT Feedback submissions attempted.
      //  Responsibility for incrementing lies OUTSIDE of the class
      //  (And watch for integer overflows)
      //  This is not used when this algorithm runs on servers
      public uint16    num_submissions_attempted

      //  This is the number of successful SCT Feedback submissions. This
      //  variable is updated by the class.
      //  This is not used when this algorithm runs on servers
      private uint16   num_submissions_succeeded

      //  This contains all the bundles of SCT data we have observed for
      //  this domain
      SCTBundle[] observed_records


      //  This function can be called to determine if we should attempt
      //  SCT Feedback for this domain.
      def should_attempt_feedback() {
        // Servers always perform feedback!
        if(operator_is_server)
          return true

        // If we have not tried in a month, try again
        if(now() - last_sct_feedback_attempt > WAIT_BETWEEN_SCT_FEEDBACK_ATTEMPTS)
          return true

        // If we have tried recently, and it seems to be working, go for it!
        if((num_submissions_succeeded / num_submissions_attempted) >
           MIN_RATIO_FOR_SCT_FEEDBACK_TO_BE_WORKING)
          return true

        // Otherwise don't try
        return false
      }

      //  For Clients, this function is called after a successful
      //  connection to an HTTPS server, with a single SCTBundle
      //  constructed from that connection's certificate chain and SCTs.
      //  For Servers, this is called after receiving SCT Feedback with
      //  all the bundles sent in the feedback.
      def insert(SCTBundle[] bundles) {
        // Do not store data for long-failing domains
        if(sct_feedback_failing_longterm()) {
          return
        }

        foreach(b in bundles) {
          if(operator_is_server) {
            if(!passes_validity_checks(b))
              return
          }

          bool have_inserted = false
          foreach(e in this.observed_records) {
            if(e.equals(b))
              return
            else if(e.approx_equals(b)) {
              have_inserted = true
              e.insert_scts(b.sct_list)
            }
          }
          if(!have_inserted)
            this.observed_records.insert(b)
        }
        SCTStoreManager.update_cache_percentage()
      }

      //  When it is time to perform SCT Feedback, the HTTPS client
      //  calls this function to get a selection of SCTBundles to send
      //  as feedback
      def get_gossip_selection() {
        if(len(observed_records) > MAX_SCT_RECORDS_TO_GOSSIP) {
          indexes = set()
          modulus = len(observed_records)
          while(len(indexes) < MAX_SCT_RECORDS_TO_GOSSIP) {
            r = randomInt() % modulus
            if(r not in indexes)
              indexes.insert(r)
          }

          return_selection = []
          foreach(i in indexes) {
            return_selection.insert(this.observed_records[i])
          }

          return return_selection
        }
        else
          return this.observed_records
      }

      def passes_validity_checks(SCTBundle b) {
        //  This function performs the validity checks specified in
        //  {{feedback-srvop}}
      }
    }

The SCTDomainEntry is responsible for handling the outcome of a
submission report for that domain using its member function:

    //  This function is called after providing SCT Feedback
    //  to a server. It is passed the feedback sent to the other party, which
    //  is the output of get_gossip_selection(), and also the SCTBundle
    //  representing the connection the data was sent on.
    //  (When this code runs on the server, connectionBundle is NULL)
    //  If the Feedback was not sent successfully, error is True
    def after_submit_to_thirdparty(error, SCTBundle[] submittedBundles,
                                   SCTBundle connectionBundle)
    {
      // Server operation in this instance is exceedingly simple
      if(operator_is_server) {
        if(error)
          return
        foreach(bundle in submittedBundles)
          bundle.num_reports_to_thirdparty++
        return
      }

      // Client behavior is much more complicated
      if(error) {
        if(sct_feedback_failing_longterm()) {
          num_feedback_loop_failures++
        }
        else if((num_submissions_succeeded / num_submissions_attempted)
                > MIN_RATIO_FOR_SCT_FEEDBACK_TO_BE_WORKING) {
          // Do nothing. num_submissions_succeeded will not be incremented
          // After enough of these failures, the ratio will fall beyond
          // acceptable
        } else {
          // The domain has begun its three-month grace period. We will
          // attempt submissions once a month
          num_feedback_loop_failures++
        }
        return
      }
      // We succeeded, so reset all of our failure states
      // Note, there is a race condition here if clear_old_data() is called
      // while this callback is outstanding.
      num_feedback_loop_failures     = 0
      if(num_submissions_succeeded != UINT16_MAX )
        num_submissions_succeeded++


      foreach(bundle in submittedBundles)
      {
        // Compare Certificate Chains, if they do not match, it counts as a
        // submission.
        if(!connectionBundle.approx_equals(bundle))
          bundle.num_reports_to_thirdparty++
        else {
          // This check ensures that a SCT Bundle is not considered reported
          // if it is submitted over a connection with the same SCTs. This
          // satisfies the constraint in Paragraph 5 of {{feedback-clisrv}}
          // Consider three submission scenarios:
          // Submitted SCTs      Connection SCTs    Considered Submitted
          // A, B                A, B               No - no new information
          // A                   A, B               Yes - B is a new SCT
          // A, B                A                  No - no new information
          if(connectionBundle.sct_list is NOT a subset of bundle.sct_list)
            bundle.num_reports_to_thirdparty++
        }
      }
    }

Instances of the SCTDomainEntry class are stored as part of a larger
class that manages the entire SCT Cache, storing them in a hashmap
keyed by domain.  This class also tracks the current size of the
cache, and will trigger cache eviction.

    //Suggestions:
    #define CACHE_PRESSURE_SAFE                   .50
    #define CACHE_PRESSURE_IMMINENT               .70
    #define CACHE_PRESSURE_ALMOST_FULL            .85
    #define CACHE_PRESSURE_FULL                   .95
    #define WAIT_BETWEEN_IMMINENT_CACHE_EVICTION  5 minutes

    class SCTStoreManager
    {
      hashmap<String, SCTDomainEntry> all_sct_entries
      uint32                         current_cache_size
      datetime                       imminent_cache_pressure_check_performed

      float current_cache_percentage() {
        return current_cache_size / MAX_CACHE_SIZE;
      }

      static def update_cache_percentage() {
        // This function calculates the current size of the cache
        // and updates current_cache_size
        /* ... perform calculations ... */
        current_cache_size = /* new calculated value */

        // Perform locking to prevent multiple of these functions being
        // called concurrently or unnecessarily
        if(current_cache_percentage() > CACHE_PRESSURE_FULL) {
            cache_is_full()
        }

        else if(current_cache_percentage() > CACHE_PRESSURE_ALMOST_FULL) {
          cache_pressure_almost_full()
        }

        else if(current_cache_percentage() > CACHE_PRESSURE_IMMINENT) {
          // Do not repeatedly perform the imminent cache pressure operation
          if(now() - imminent_cache_pressure_check_performed >
              WAIT_BETWEEN_IMMINENT_CACHE_EVICTION) {
            cache_pressure_is_imminent()
          }
        }
      }
    }

The SCTStoreManager contains a function that will be called
periodically in the background, iterating through all SCTDomainEntry
objects and performing maintenance tasks. It removes data for domains
we have not contacted in a long time. This function is not intended to
clear data if the cache is getting full, separate functions are used
for that.

    // Suggestions:
    #define TIME_UNTIL_OLD_SUBMITTED_SCTDATA_ERASED     3 months
    #define TIME_UNTIL_OLD_UNSUBMITTED_SCTDATA_ERASED   6 months

    def clear_old_data()
    {
      foreach(domainEntry in all_sct_stores)
      {
        // Queue proof fetches
        if(proof_fetching_enabled) {
          foreach(sctBundle in domainEntry.observed_records) {
            if(!sctBundle.has_been_fully_resolved_to_sths()) {
              foreach(s in bundle.sct_list) {
                if(!s.has_been_resolved_to_sth && !s.proof_outstanding) {
                  sct.proof_outstanding = True
                  queue_inclusion_proof(sct, inclusion_proof_callback)
                }
              }
            }
          }
        }

        // Do not store data for domains who are not supporting SCT
        if(!operator_is_server
           && domainEntry.sct_feedback_failing_longterm())
        {
          // Note that reseting these variables every single time is
          // necessary to avoid a bug
          all_sct_stores[domainEntry].num_submissions_attempted      = 0
          all_sct_stores[domainEntry].num_submissions_succeeded      = 0
          delete all_sct_stores[domainEntry].observed_records
          all_sct_stores[domainEntry].observed_records               = NULL
        }

        // This check removes successfully submitted data for
        // old domains we have not dealt with in a long time
        if(domainEntry.num_submissions_succeeded > 0
           && now() - domainEntry.last_contact_for_domain
              > TIME_UNTIL_OLD_SUBMITTED_SCTDATA_ERASED)
        {
          all_sct_stores.remove(domainEntry)
        }

        // This check removes unsuccessfully submitted data for
        // old domains we have not dealt with in a very long time
        if(now() - domainEntry.last_contact_for_domain
           > TIME_UNTIL_OLD_UNSUBMITTED_SCTDATA_ERASED)
        {
          all_sct_stores.remove(domainEntry)
        }

    SCTStoreManager.update_cache_percentage()
    }

Inclusion Proof Fetching is handled fairly independently

    // This function is a callback invoked after an inclusion proof
    // has been retrieved. It can exist on the SCT class or independently,
    // so long as it can modify the SCT class' members
    def inclusion_proof_callback(inclusion_proof, original_sct, error)
    {
      // Unlike the STH code, this counter must be incremented on the
      // callback as there is a race condition on using this counter in the
      // cache_* functions.
      original_sct.proof_attempts++
      original_sct.proof_outstanding = False
      if(!error) {
        original_sct.has_been_resolved_to_sth = True
        insert_to_sth_datastore(inclusion_proof.new_sth)
      } else {
        original_sct.proof_failure_count++
      }
    }


If the cache is getting full, these three member functions of the
SCTStoreManager class will be used.

    // -----------------------------------------------------------------
    // This function is called when the cache is not yet full, but is
    // nearing it. It prioritizes deleting data that should be safe
    // to delete (because it has been shared with the site or resolved
    // to an STH)
    def cache_pressure_is_imminent()
    {
      bundlesToDelete = []
      foreach(domainEntry in all_sct_stores) {
        foreach(sctBundle in domainEntry.observed_records) {

          if(proof_fetching_enabled) {
            // First, queue proofs for anything not already queued.
            if(!sctBundle.has_been_fully_resolved_to_sths()) {
              foreach(sct in bundle.sct_list) {
                if(!sct.has_been_resolved_to_sth
                   && !sct.proof_outstanding) {
                  sct.proof_outstanding = True
                  queue_inclusion_proof(sct, inclusion_proof_callback)
                }
              }
            }

            // Second, consider deleting entries that have been fully
            // resolved.
            else {
              bundlesToDelete.append( Struct(domainEntry, sctBundle) )
            }
          }

          // Third, consider deleting entries that have been successfully
          // reported
          if(sctBundle.num_reports_to_thirdparty > 0) {
            bundlesToDelete.append( Struct(domainEntry, sctBundle) )
          }
        }
      }

      // Third, delete the eligible entries at random until the cache is
      // at a safe level
      uint recalculateIndex                = 0
      #define RECALCULATE_EVERY_N_OPERATIONS 50

      while(bundlesToDelete.length > 0 &&
            current_cache_percentage() > CACHE_PRESSURE_SAFE) {
        uint rndIndex = rand() % bundlesToDelete.length
        bundlesToDelete[rndIndex].domainEntry.observed_records.remove(bundlesToDelete[rndIndex].sctBundle)
        bundlesToDelete.removeAt(rndIndex)

        recalculateIndex++
        if(recalculateIndex % RECALCULATE_EVERY_N_OPERATIONS == 0) {
          update_cache_percentage()
        }
      }

      // Finally, tell the proof fetching engine to go faster
      if(proof_fetching_enabled) {
        // This function would speed up proof fetching until an
        // arbitrary time has passed. Perhaps until it has fetched
        // proofs for the number of items currently in its queue? Or
        // a percentage of them?
        proof_fetch_faster_please()
      }

      update_cache_percentage();
    }

    // -----------------------------------------------------------------
    // This function is called when the cache is almost full. It will
    // evict entries at random, while attempting to save entries that
    // appear to have proof fetching failures
    def cache_pressure_almost_full()
    {
      uint recalculateIndex                = 0
      uint savedRecords                    = 0
      #define RECALCULATE_EVERY_N_OPERATIONS 50

      while(all_sct_stores.length > savedRecords &&
            current_cache_percentage() > CACHE_PRESSURE_SAFE) {
        uint rndIndex1 = rand() % all_sct_stores.length
        uint rndIndex2 = rand() % all_sct_stores[rndIndex1].observed_records.length

        if(proof_fetching_enabled) {
          if(all_sct_stores[rndIndex1].observed_records[rndIndex2].max_proof_failures() >
             MIN_PROOF_FAILURES_CONSIDERED_SUSPICIOUS) {
            savedRecords++
            continue
          }
        }

        // If proof fetching is not enabled we need some other logic
        else {
          if(sctBundle.num_reports_to_thirdparty == 0) {
            savedRecords++
            continue
          }
        }

        all_sct_stores[rndIndex1].observed_records.removeAt(rndIndex2)
        if(all_sct_stores[rndIndex1].observed_records.length == 0) {
          all_sct_stores.removeAt(rndIndex1)
        }

        recalculateIndex++
        if(recalculateIndex % RECALCULATE_EVERY_N_OPERATIONS == 0) {
          update_cache_percentage()
        }
      }

      update_cache_percentage();
    }

    // -----------------------------------------------------------------
    // This function is called when the cache is full, and will evict
    // cache entries at random
    def cache_is_full()
    {
      uint recalculateIndex                = 0
      #define RECALCULATE_EVERY_N_OPERATIONS 50

      while(all_sct_stores.length > 0 &&
            current_cache_percentage() > CACHE_PRESSURE_SAFE) {
        uint rndIndex1 = rand() % all_sct_stores.length
        uint rndIndex2 = rand() % all_sct_stores[rndIndex1].observed_records.length

        all_sct_stores[rndIndex1].observed_records.removeAt(rndIndex2)
        if(all_sct_stores[rndIndex1].observed_records.length == 0) {
          all_sct_stores.removeAt(rndIndex1)
        }


        recalculateIndex++
        if(recalculateIndex % RECALCULATE_EVERY_N_OPERATIONS == 0) {
          update_cache_percentage()
        }
      }

      update_cache_percentage();
    }


# IANA considerations

\[ TBD \]

# Contributors

The authors would like to thank the following contributors for
valuable suggestions: Al Cutter, Andrew Ayer, Ben Laurie, Benjamin
Kaduk, Graham Edgecombe, Josef Gustafsson, Karen Seo, Magnus Ahltorp,
Steven Kent, Yan Zhu.

# ChangeLog

## Changes between ietf-03 and ietf-04

- No changes.

## Changes between ietf-02 and ietf-03

- TBD's resolved.
- References added.
- Pseduocode changed to work for both clients and servers.

## Changes between ietf-01 and ietf-02

- Requiring full certificate chain in SCT Feedback.
- Clarifications on what clients store for and send in SCT Feedback
  added.
- SCT Feedback server operation updated to protect against DoS attacks
  on servers.
- Pre-Loaded vs Locally Added Anchors explained.
- Base for well-known URL's changed.
- Remove all mentions of monitors -- gossip deals with auditors.
- New sections added: Trusted Auditor protocol, attacks by actively
  malicious log, the Dual-CA compromise attack, policy
  recommendations,

## Changes between ietf-00 and ietf-01

- Improve language and readability based on feedback from Stephen
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
