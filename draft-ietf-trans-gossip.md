---
title: Gossiping in CT
docname: draft-ietf-trans-gossip-00
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
  RFC6962:
  RFC7159:

informative:
  THREAT-ANALYSIS:
    title: "Threat Analysis for Certificate Transparency"
    author:
      -
        ins: S. Kent
        name: Stephen Kent
    date: 2015
    target: https://datatracker.ietf.org/doc/draft-ietf-trans-threat-analysis/

--- abstract

This document describes three gossiping mechanisms for Certificate
Transparency (CT) {{RFC6962}}: SCT Feedback, STH Pollination and
a Trusted Auditor Relationship.

SCT Feedback enables HTTPS clients to share Signed Certificate
Timestamps (SCTs) (Section 3.2 of {{RFC6962}}) with CT auditors in a
privacy-preserving manner by sending SCTs to originating HTTPS servers,
which in turn share them with CT auditors.

In STH Pollination, HTTPS clients use HTTPS servers as pools sharing
Signed Tree Heads (STHs) (Section 3.5 of {{RFC6962}}) with other
connecting clients in the hope that STHs will find their way to
auditors and monitors.

HTTPS clients in a Trusted Auditor Relationship share SCTs and STHs
with trusted auditors or monitors directly, with expectations of
privacy sensitive data being handled according to whatever privacy
policy is agreed on between client and trusted party.

--- middle

# Introduction

The purpose of the protocols in this document is to detect misbehavior
by CT logs. In particular, CT logs can misbehave either by rewriting
history or by presenting a "split view" of their operations, also
known as a partitioning attack {{THREAT-ANALYSIS}}. CT provides
mechanisms for detection of these misbehaviors, but only if the
community dependent on the log knows what to do with them. In order
for the community to effectively detect log misbehavior, it needs a
well-defined way to "gossip" about the activity of the logs that makes
use of the available mechanisms.

One of the major challenges of any gossip protocol is limiting damage
to user privacy. The goal of CT gossip is to publish and distribute
information about the logs and their operations, but not to leak any
additional information about the operation of any of the other
participants. Privacy of consumers of log information (in particular,
of web browsers and other TLS clients) should not be damaged by
gossip.

This document presents three different, complementary mechanisms for
non-log players in the CT ecosystem to exchange information about logs
in a manner that preserves the privacy of the non-log players
involved. They should provide protective benefits for the system as a
whole even if their adoption is not universal.

# Overview

Public append-only untrusted logs have to be monitored for
consistency, i.e., that they should never rewrite history.
Additionally, monitors and other log clients need to exchange
information about monitored logs in order to be able to detect a
partitioning attack.

A partitioning attack is when a log serves different views of the log
to different clients. Each client would be able to verify the
append-only nature of the log, while in the extreme case being the only
client seeing this particular view.

Gossiping about what's known about logs helps solve the problem of
detecting malicious or compromised logs mounting such a partitioning
attack. We want some side of the partitioned tree, and ideally both
sides, to see the other side.

Disseminating known information about a log poses a potential threat
to the privacy of end users. Some data of interest (e.g. SCTs) are
linkable to specific log entries and thereby to specific sites, which
makes them privacy-sensitive. Gossip has to take
privacy considerations into account in order not to leak associations
between users of the log (e.g., web browsers) and certificate holders
(e.g., web sites). Even sharing STHs (which do not link to specific
log entries) can be problematic -- user tracking by fingerprinting
through rare STHs is one potential attack.

However, there are avenues by which information can be shared that is 
not damaging to user privacy. For example, there is no loss in privacy 
if a client sends SCTs for a
given site to the site corresponding to the SCT, because the site's
access logs would already indicate that the client is accessing that
site. In this way a site can accumulate records of SCTs that have been
issued by various logs for that site, providing a consolidated
repository of SCTs which can be queried by auditors.

As another example, sharing an STH is considered reasonably safe from a privacy
perspective as long as the same STH is shared by a large number of
other clients. This "safety in numbers" is achieved by requiring
gossip only for STHs of a certain "freshness" and limiting the
frequency by which logs can issue STHs.

# Terminology and data flow

This document relies on terminology and data structures defined in
{{RFC6962}}, including STH, SCT, Version, LogID, SCT timestamp,
CtExtensions, SCT signature, Merkle Tree Hash.

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

# Who gossips {#who}

- HTTPS clients and servers (SCT Feedback and STH Pollination)
- HTTPS servers and CT auditors (SCT Feedback)
- CT auditors and monitors (Trusted Auditor Relationship)

Additionally, some HTTPS clients may engage with an auditor who they
trust with their privacy:

- HTTPS clients and CT auditors (Trusted Auditor Relationship)

# What to gossip about and how {#whathow}

There are three separate gossip streams:

- SCT Feedback, transporting SCTs and certificate chains from HTTPS
  clients to CT auditors/monitors via HTTPS servers.

- STH Pollination, HTTPS clients and CT auditors/monitors using HTTPS
  servers as STH pools for exchanging STHs.

- Trusted Auditor Stream, HTTPS clients communicating directly with
  trusted CT auditors/monitors sharing SCTs, certificate chains and
  STHs.

# Gossip Mechanisms

## SCT Feedback

The goal of SCT Feedback is for clients to share SCTs and certificate
chains with CT auditors and monitors in a privacy-preserving manner.
SCT Feedback is the most privacy-preserving gossip mechanism, as it
does not share any additional data whatsoever with any third party. 

HTTPS clients store SCTs and certificate chains they see, and later
send them to the originating HTTPS server by posting them to a
.well-known URL. This is described in {{feedback-clisrv}}. Note that
clients send the same SCTs and chains to servers multiple times with
the assumption that a potential man-in-the-middle attack eventually
will cease, and an honest server will receive collected malicious
SCTs and certificate chains.

HTTPS servers store SCTs and certificate chains received from clients
and later share them with CT auditors by either posting them or making
them available on a .well-known URL. This is described in
{{feedback-srvaud}}.

### HTTPS client to server {#feedback-clisrv}

An HTTPS client connects to an HTTPS server for a particular
domain. The client receives a set of SCTs as part of the TLS
handshake. The client MUST discard SCTs that are not signed by a known
log and SHOULD store the remaining SCTs together with the
corresponding certificate chain for later use in feedback.

When the client later reconnects to any HTTPS server for the same
domain, it again receives a set of SCTs. The client MUST add new SCTs
from known logs to its store of SCTs for the server. The client MUST
send to the server the ones in the store that are for that server and
were not received from that server.

\[ TODO: fix the above paragraph -- it is vague and confusing.  maybe
  an example including a client caching at most one SCT per host+log
  would clarify \]

Note that the SCT store also contains SCTs received in certificates.

The client MUST NOT send the same set of SCTs to the same server more
often than TBD.
\[benl: "sent to the server" only really counts if the server presented a valid SCT in the handshake and the certificate is known to be unrevoked (which will be hard for a MitM to sustain)\]
\[TODO: expand on rate/resource limiting motivation\]

Refer to {#pooling-policy-recommendations} for recommendations about 
strategies.

An SCT MUST NOT be sent to any other HTTPS server than one serving the
domain that the certificate signed by the SCT refers to. This would
lead to two types of privacy leaks. First, the server receiving the
SCT would learn about other sites visited by the HTTPS
client. Secondly, auditors or monitors receiving SCTs from the HTTPS
server would learn information about the other HTTPS servers visited
by its clients.

If the HTTPS client has configuration options for not sending cookies
to third parties, SCTs of third parties MUST be treated as cookies with respect to this
setting. This prevents third party tracking through the use of SCTs/certificates,
which would bypass the cookie policy.

SCTs and corresponding certificates are POSTed to the originating
HTTPS server at the well-known URL:

    https://<domain>/.well-known/ct/v1/sct-feedback

The data sent in the POST is defined in {{feedback-dataformat}}.

HTTPS servers perform a number of sanity checks on SCTs from clients
before storing them:

  1. if a bit-wise compare of an SCT plus chain matches a pair already
  in the store, this SCT and chain pair MAY be discarded

  1. if the SCT can't be verified to be a valid SCT for the
  accompanying leaf cert, issued by a known log, the SCT SHOULD be
  discarded

  1. if the leaf cert is not for a domain that the server is
  authoritative for, the SCT MUST be discarded

Check number 1 is for detecting duplicates and minimizing processing and storage by the server. It's important to note
that the check should be on pairs of SCT and chain in order to catch
different chains accompanied by the same SCT. This mis-matched chain 
information may be useful as a diagnostic tool for HTTPS server operators.

Check number 2 is to prevent spamming attacks where an adversary
can fill up the store prior to attacking a client, or a denial of
service attack on the server's storage space.

Check number 3 is to help malfunctioning clients from leaking which
sites they visit and additionally to prevent spamming attacks.

Note that an HTTPS server MAY perform a certificate chain validation
on a submitted certificate chain, and if it matches a trust root
configured on the server (but whose leaf cert is otherwise unknown to the server), the
HTTPS server MAY store the certificate chain and MAY choose to store
any submitted SCTs even if they are unable to be verified. The risk of
spamming and denial of service can be mitigated by configuring the
server with all known acceptable certificates (or certificate hashes).
This information may enable a HTTPS server operator to detect attacks
or unusual behavior of Certificate Authorities even outside the Certificate
Transparency ecosystem.

### HTTPS server to auditors {#feedback-srvaud}

HTTPS servers receiving SCTs from clients SHOULD share SCTs and
certificate chains with CT auditors by either providing the well-known
URL:

    https://<domain>/.well-known/ct/v1/collected-sct-feedback

or by HTTPS POSTing them to a number of preconfigured auditors. This
allows an HTTPS server to choose between an active push model or a
passive pull model.

The data received in a GET of the well-known URL or sent in the POST
is defined in {{feedback-dataformat}}.

HTTPS servers SHOULD share all SCTs and accompanying certificate
chains they see that pass the checks in {{feedback-clisrv}}. If this
is an infeasible amount of data, the server may choose to expire
submissions according to an undefined policy. Suggestions for such
a policy can be found in {#pooling-policy-recommendations}.

HTTPS servers MUST NOT share any other data that they may learn from
the submission of SCT Feedback by HTTPS clients.

Auditors SHOULD provide the following URL accepting HTTPS POSTing of
SCT feedback data:

    https://<auditor>/ct/v1/sct-feedback

Auditors SHOULD regularly poll HTTPS servers at the well-known
collected-sct-feedback URL. The frequency of the polling and how to
determine which domains to poll is outside the scope of this
document. However, the selection MUST NOT be influenced by potential
HTTPS clients connecting directly to the auditor. For example, if a poll
to example.com occurs directly after a client submits an SCT for example.com, 
an adversary observing the auditor can trivially conclude the activity 
of the client.

### SCT Feedback data format {#feedback-dataformat}

The data shared between HTTPS clients and servers, as well as between
HTTPS servers and CT auditors/monitors, is a JSON object {{RFC7159}}
with the following content:

- sct_feedback: An array of objects consisting of

  - x509_chain: An array of base64-encoded X.509 certificates. The
    first element is the end-entity certificate, the second chains to
    the first and so on.

  - sct_data: An array of objects consisting of the base64
    representation of the binary SCT data as defined in {{RFC6962}}
    Section 3.2.

The 'x509_chain' element MUST contain the leaf certificate and the
full chain to a known root.

\[ TBD: There was discussion about including a few field for client->server 
reporting, which is the exact set and order of certificates sent by the HTTPS 
server to the client. This is additional diagnostic information that a HTTPS server
could use to check it's deployment... but is pretty much useless to CT or gossip.
Right now we're not including this, but we're polling server operators to see if they
would welcome this data.]

## STH pollination

The goal of sharing Signed Tree Heads (STHs) through pollination is to
share STHs between HTTPS clients, CT auditors, and monitors in a
privacy-preserving manner.

HTTPS servers supporting the protocol act as STH pools. HTTPS clients
and others in the possession of STHs should pollinate STH pools by
sending STHs to them, and retrieving new STHs to send to new servers.
CT auditors and monitors should retrieve STHs from pools by
downloading STHs from them.

STH Pollination is carried out by sending STHs to HTTPS servers
supporting the protocol, and retrieving new STHs. In the case of HTTPS
clients, STHs are sent in an already established TLS session. This
makes it hard for an attacker to disrupt STH gossiping without also
disturbing ordinary secure browsing (https://). This is discussed more 
in {#blocking-policy-frustrating}.

STHs are sent by POSTing them to the .well-known URL:

    https://<domain>/.well-known/ct/v1/sth-pollination

The data sent in the POST is defined in {{sth-pollination-dataformat}}.

The response contains zero or more STHs in the same format, described
in {{sth-pollination-dataformat}}.

An HTTPS client may acquire STHs by several methods:

- in replies to pollination POSTs;
- asking its supported logs for the current STH directly or indirectly;
- resolving a SCT and certificate to a STH via an inclusion proof
- resolving one STH to another via a consistency proof

HTTPS clients (who have STHs), CT auditors, and monitors SHOULD
pollinate STH pools with STHs. Which STHs to send and how often
pollination should happen is regarded as undefined policy with 
the exception of privacy concerns explained in the 
next section. Suggestions for the policy may be found in 
{#pooling-policy-recommendations}.

An HTTPS client could be tracked by giving it a unique or rare STH.
To address this concern, we place restrictions on different components
of the system to ensure an STH will not be rare.

- Logs cannot issue STHs too frequently. This is restricted to 1 per
  hour.
- HTTPS clients silently ignore STHs which are not fresh.

An STH is considered fresh iff its timestamp is less than 14 days in
the past. Given a maximum STH issuance rate of one per hour, an
attacker has 336 unique STHs per log for tracking. Clients MUST ignore
STHs older than 14 days. We consider STHs within this validity window to 
be personally identifiable data, and STHs outside this window not 
personally identifiable.

A log may cease operation, in which case there will soon be no STH within 
the validity window. Clients SHOULD perform all three methods of gossip 
about a log that has ceased operation - it is possible the log was still 
compromised and gossip can detect that. STH Pollination is the one mechanism where 
a client must know about a log shutdown. A client who does not know about a 
log shutdown MUST NOT attempt any heuristic to detect a shutdown. Instead the 
client MUST be informed about the shutdown from a verifiable source (e.g. a 
software update). The client SHOULD be provided the final STH issued by the 
log and SHOULD resolve SCTs and STHs to this final STH. If an SCT or STH cannot 
be resolved to the final STH... XXX?

\[
tjr: Shit.  I think we need an escape valve. Assume someone compromises a log, 
isolates a client until shutdown, then the client goes off and does its happy 
thing on a clean network.

It requests STH resolution of the split view to the non-split view.  The legit 
log can't do that. It returns a 500. What does the client do?  In a perfect world, 
the log would see a signed STH it doesn't know about and report on itself. We shouldn't 
assume a perfect world though.

How do we detect it?

Another example is a non-shut down log that gets own. Client sees a split view, 
then goes to a clean network.  It attempts to resolve an STH to a current one 
with the legit log.  The legit log can't do it. Returns a 500. Again, perfect 
world - log self-reports itself. How do we solve this in an imperfect world?

Do we specify a heuristic like "If you can't resolve an STH after trying N times, 
during which you do get successful responses from the log, fuck it just send it 
to Google and the EFF"?
]

When multiplied by the number of logs that a client accepts STHs for,
this number of unique STHs grow and the negative privacy implications
grow with it. It's important that this is taken into account when logs
are chosen for default settings in HTTPS clients. This concern is 
discussed upon in {#privacy-sth-interaction}.

\[TBD urge HTTPS clients to store STHs retrieved in responses?\]

\[TBD share inclusion proofs and consistency proofs too?\]

### HTTPS Clients and Proof Fetching

\[
tjr: I am establishing a term here "Proof Fetching" to refer to the part of STH Pollination that involves getting inclusion or consistency proofs.
This avoids us having to say "resolve SCTs or Historical STHs" everywhere.
\]

There are two types of proofs a client may retrieve.

An HTTPS client will retrieve SCTs from an HTTPS server, and must obtain
an inclusion proof to an STH in order to verify the promise made by
the SCT. 

An HTTPS client may receive SCT bundled with an inclusion proof to a 
historical STH via an unspecified future mechanism. Because this historical 
STH is considered personally identifiable information per above, the client 
must obtain a consistency proof to a more recent STH.

If a client requested either proof directly from a log or auditor, it would reveal 
the client's browsing habits to a third party. To mitigate
this risk, an HTTPS client MUST retrieve the proof in a manner that
disguises the client.

Depending on the client's DNS provider, DNS may provide an appropriate
intermediate layer that obfuscates the linkability between the user of
the client and the request for inclusion (while at the same time
providing a caching layer for oft-requested inclusion proofs.)

Anonymity networks such as Tor also present a mechanism for a client to
anonymously retrieve a proof from an auditor or log.

### STH Pollination without Proof Fetching

An HTTPS client MAY participate in STH Pollination without fetching proofs. 
In this situation, the client receives STHs from a server,
applies the same validation logic to them (signed by a known log, within a validity window)
and will later pass them to a HTTPS server.

When operating in this fashion, the HTTPS client is promoting gossip for 
Certificate Transparency, but derives no direct benefit itself. In comparison, 
a client who resolves SCTs or historical STHs to recent STHs and pollinates them
is assured that if it was attacked, there is a probability that the ecosystem will
detect and respond to the attack (by distrusting the log).

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

- sths -- an array of 0 or more fresh STH objects
  \[XXX recently collected\] from the log associated with log_id. Each
  of these objects consists of

  - sth_version: Version as defined in {{RFC6962}} Section 3.2, as a
    number. The version of the protocol to which the sth_gossip object
    conforms.

  - tree_size: The size of the tree, in entries, as a number.

  - timestamp: The timestamp of the STH as defined in {{RFC6962}}
    Section 3.2, as a number.

  - sha256_root_hash: The Merkle Tree Hash of the tree as defined in
    {{RFC6962}} Section 2.1, as a base64 encoded string.

  - tree_head_signature: A TreeHeadSignature as defined in
    {{RFC6962}} Section 3.5 for the above data, as a base64 encoded
    string.

  - log_id: LogID as defined in {{RFC6962}} Section 3.2, as a base64
    encoded string.

\[XXX An STH is considered recently collected iff TBD.\]

## Trusted Auditor Stream

HTTPS clients MAY send SCTs and cert chains, as well as STHs, directly
to auditors. Note that there are privacy implications in doing so,
these are outlined in {{privacy-SCT}} and {{privacy-trusted-auditors}}.

The most natural trusted auditor arrangement arguably is a web browser
that is "logged in to" a provider of various internet
services. Another equivalent arrangement is a trusted party like a
corporation to which an employee is connected through a VPN or by
other similar means. A third might be individuals or smaller groups of
people running their own services. In such a setting, retrieving proofs 
from that third party 
could be considered reasonable from a privacy perspective. The HTTPS
client does its own auditing and might additionally share SCTs and
STHs with the trusted party to contribute to herd immunity. Here, the
ordinary {{RFC6962}} protocol is sufficient for the client to do the
auditing while SCT Feedback and STH Pollination can be used in whole
or in parts for the gossip part.

Another well established trusted party arrangement on the internet
today is the relation between internet users and their providers of
DNS resolver services. DNS resolvers are typically provided by the
internet service provider (ISP) used, which by the nature of name
resolving already know a great deal about which sites their users
visit. As mentioned in Section XXX, in order for HTTPS clients to be
able to retrieve proofs in a privacy
preserving manner, logs could expose a DNS interface in addition to
the ordinary HTTPS interface. An informal writeup of such a protocol
can be found at XXX.


### Trusted Auditor data format

\[TBD specify something here or leave this for others?\]

# 3-Method Ecosystem

The use of three distinct methods for monitoring logs may seem excessive,
but each represents a needed component in the CT ecosystem. To understand
why, the drawbacks of each component must be outlined. In this discussion
we assume that an attacker knows which mechanisms an HTTPS client and HTTPS
server implement.

## SCT Feedback

SCT Feedback requires the cooperation of HTTPS clients and more importantly
HTTPS servers. Although SCT Feedback does require a significant amount of 
server-side logic to respond to the corresponding APIs, this functionality 
does not require customization, so it may be pre-provides and work out of 
the box. However, to take full advantage of the system, a HTTPS server would
wish to perform some configuration to optimize its operation:

- Minimize its disk commitment by whitelisting known SCTs and
  certificate chains
- Maximize its chance of detecting a misissued certificate by configuring
  a trust store of CAs
- Establish a "push" mechanism for POSTing SCTs to Auditors and Monitors

These configuration needs, and the simple fact that it would require some
deployment of software, mean that some percentage of HTTPS servers will not
deploy SCT Feedback.

If SCT Feedback was the only mechanism in the ecosystem, any server that
did not implement the feature, would open itself and its users to attack 
without any possibility of detection.

If SCT Feedback was not deployed, users who wished to have the strongest
measure of privacy protection (by disabling STH Pollination Proof Fetching
and forgoing a Trusted Auditor) could be attacked without risk of detection. 

## STH Pollination

STH Pollination requires the cooperation of HTTPS clients, HTTPS servers,
and logs.

For a client to fully participate in STH Pollination, and have this mechanism 
detect attacks against it, the client must have a way to safely perform 
Proof Fetching in a privacy preserving manner. The client may pollinate STHs 
it receives without performing Proof Fetching, 
but we do not consider this option in this section.

HTTPS Servers must deploy software (although, as in the case with SCT Feedback
this logic can be pre-provided) and commit some configurable amount of disk
space to the endeavor.

Logs must provide access to clients to query proofs in a privacy
preserving manner, most likely through DNS.

Unlike SCT Feedback, the STH Pollination mechanism is not hampered if only a
minority of HTTPS servers deploy it. However, it makes an assumption that
an HTTPS client performs anonymized Proof Fetching (such as the DNS mechanism 
discussed). However, any manner that is anonymous for some (such as clients 
who use shared DNS services such as a large ISP), may not be anonymous for others. 
For instance, if DNS requests are avoided due to proxy configuration files, 
proof requests over DNS leak data that otherwise is not disclosed. For this 
reason, some percentage of HTTPS clients may choose to not enable the Proof Fetching
component of STH pollination.  (Although they can still request and send STHs 
among participating HTTPS servers, as mentioned earlier this affords them no 
direct benefit.) 

If STH Pollination was the only mechanism deployed, users that disable it
would be able to be attacked without risk of detection.

If STH Pollination was not deployed, HTTPS Clients visiting
HTTPS Servers who did not deploy SCT Feedback could be attacked without risk
of detection.

## Trusted Auditor Relationship

The Trusted Auditor Relationship is expected to be the rarest gossip
mechanism, as an HTTPS Client is providing an unadulterated report of its
browsing history to a third party. While there are valid and common reasons
for doing so, there is no appropriate way to enter into this relationship
without retrieving informed consent from the user.

However, the Trusted Auditor Relationship mechanism still provides value
to a class of HTTPS Clients. For example, web crawlers have no concept of
a "user" and no expectation of privacy. Organizations already performing network 
monitoring for anomalies or attacks can run their own Trusted Auditor for 
the same purpose with marginal increase in privacy concerns.

The ability to change one's Trusted Auditor
is a form of Trust Agility that allows a user to choose who to trust, and
be able to revise that decision later without consequence. A Trusted Auditor
connection can be made more confidential than DNS (through the use of TLS), and
can even be made (somewhat) anonymous through the use of anonymity services
such as Tor. (Note that this does ignore the de-anonymization possibilities
available from viewing a user's browsing history.)

If the Trusted Auditor relationship was the only mechanism deployed, users
who do not enable it (the majority) would be able to be attacked without
risk of detection.

If the Trusted Auditor relationship was not deployed, crawlers and organizations 
would build it themselves for their own needs. By standardizing it, users who 
wish to opt-in (for instance those unwilling to participate fully in STH Pollination) 
can have an interoperable standard they can use to choose and change their trusted auditor.

## Interaction

The interactions of the mechanisms is thus outlined:

HTTPS Clients can be attacked without risk of detection if they do not
participate in any of the three mechanisms.

HTTPS Clients are afforded the greatest chance of detecting an attack when they
either participate in STH Pollination with Proof Fetching or have a Trusted 
Auditor relationship. Participating in SCT Feedback enables a HTTPS Client 
to assist in detecting the exact target of an attack, although they do not 
gain any direct benefit from it.

HTTPS Servers that omit SCT Feedback may never learn about targeted attacks against them,
even if the attack occurred and the log distrusted. They do gain some herd immunity, 
enabling them to detect attacks, through their clients participating in STH Pollination or a Trusted Auditor Relationship.

When HTTPS Servers omit SCT feedback, it allow a portion of their users to be
attacked without detection; the vulnerable users are those who do not participate in STH
Pollination with Proof Fetching and that not have a Trusted Auditor relationship.

# Security considerations

## Censorship/Blocking considerations

We assume a network attacker who is able to fully control the client's 
internet connection for some period of time - including selectively 
blocking requests to certain hosts and truncating TLS connections based 
on information observed or guessed about client behavior. In order to 
successfully detect log misbehavior, the gossip mechanisms must still work 
even in these conditions.

There are several gossip connections that can be blocked:

1. Clients sending SCTs to servers in SCT Feedback
2. Servers sending SCTs to auditors in SCT Feedback (server push mechanism)
3. Servers making SCTs available to auditors (auditor pull mechanism)
4. Clients fetching proofs in STH Pollination 
5. Clients sending STHs to servers in STH Pollination
6. Servers sending STHs to clients in STH Pollination
7. Clients sending SCTs to Trusted Auditors

If a party cannot connect to another party, it can be assured that the 
connection did not succeed. While it may not have been maliciously blocked, it
knows the transaction did not succeed. Mechanisms which result in a positive 
affirmation from the recipient that the transaction succeeded allow confirmation 
that a connection was not blocked. In this situation, the party can factor this 
into strategies suggested in {#pooling-policy-recommendations} and in 
{#blocking-policy-response}.  

The connections that allow positive affirmation are 1, 2, 4, 5, and 7.

More insidious is blocking the connections that do not allow positive 
confirmation: 3 and 6. An attacker may truncate a or drop a response from a 
server to a client, such that the server believes it has shared data with the 
recipient, when it has not. However, in both scenatios (3 and 6), the server
cannot distinguish the client as a cooperating member of the CT ecosystem or
as an attacker performing a sybil attack, aiming to flush the server's data 
store.  Therefore the fact that these connections can be undetectably blocked 
does not actually alter the threat model of servers responding to these 
requests. The choice of algorithm to release data is crucial to protect against 
these attacks, strategies are suggested in {#pooling-policy-recommendations}.

Handling censorship and network blocking (which is indistinguishable from 
network error) is relegated to the implementation policy chosen by clients.
Suggestions for client behavior are specified in {#blocking-policy-recommendations}.

## Privacy considerations

The most sensitive relationships in the CT ecosystem are the
relationships between HTTPS clients and HTTPS servers. Client-server
relationships can be aggregated into a network graph with potentially
serious implications for correlative de-anonymisation of clients and
relationship-mapping or clustering of servers or of clients.

### Privacy and SCTs {#privacy-SCT}

An SCT contains information that links it to a particular web
site. Because the client-server relationship is sensitive, gossip
between clients and servers about unrelated SCTs is risky. Therefore,
a client with an SCT for a given server should transmit that
information in only two channels: to a server associated with the SCT
itself; and to a trusted CT auditor, if one exists.

### Privacy in SCT Feedback {#privacy-feedback}

SCTs introduce yet another mechanism for HTTPS servers to store state
on an HTTPS client, and potentially track users. HTTPS clients which
allow users to clear history or cookies associated with an origin MUST
clear stored SCTs associated with the origin as well.

Auditors should treat all SCTs as sensitive data. SCTs received
directly from an HTTPS client are especially sensitive, because the
auditor is a trusted by the client to not reveal their associations
with servers. Auditors MUST NOT share such SCTs in any way, including
sending them to an external log, without first mixing them with
multiple other SCTs learned through submissions from multiple other
clients. Suggestions for mixing SCTs are presented in {#pooling-policy-recommendations}.

There is a possible fingerprinting attack where a log issues a unique
SCT for targeted log client(s). A colluding log and HTTPS server
operator could therefore be a threat to the privacy of an HTTPS
client. Given all the other opportunities for HTTPS servers to
fingerprint clients -- TLS session tickets, HPKP and HSTS headers,
HTTP Cookies, etc. -- this is acceptable.

The fingerprinting attack described above could be avoided by
requiring that logs i) MUST return the same SCT for a given cert chain
({{RFC6962}} Section 3) and ii) use a deterministic signature scheme
when signing the SCT ({{RFC6962}} Section 2.1.4).

There is another similar fingerprinting attack where an HTTPS server
tracks a client by using a variation of cert chains. The risk for this
attack is accepted on the same grounds as the unique SCT attack
described above. \[XXX any mitigations possible here?\]

### Privacy for HTTPS clients performing STH Proof Fetching

An HTTPS client performing Proof Fetching should only request proofs 
from a CT log that it accepts SCTs from. An HTTPS client should
regularly [XXX how regularly? This has operational implications for log
operators] request an STH from all logs it is willing to accept, even
if it has seen no SCTs from that log.

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
STH for a targeted log auditor or HTTPS client. This is similar to the
fingerprinting attack described in {{privacy-feedback}}, but it is
mitigated by the following factors:

- the relationship between auditors and logs is not sensitive in the
  way that the relationship between HTTPS clients and HTTPS servers
  is;

- because auditors regularly exchange STHs with each other, the
  re-appearance of a targeted STH from some auditor does not imply
  that the auditor was the original one targeted by the log;

- an HTTPS client's relationship to a log is not sensitive in the way
  that its relationship to an HTTPS server is. As long as the client
  does not query the log for anything other than individual STHs, the
  client should not leak anything else to the log itself. However, a
  log and an HTTPS server which are collaborating could use this
  technique to fingerprint a targeted HTTPS client.

Note that an HTTPS client in the configuration described in this
document doesn't make direct use of the STH itself. Its fetching of
the STH and reporting via STH Pollination provides a benefit to the CT
ecosystem as a whole by providing oversight on logs, but the HTTPS
client itself will not necessarily derive direct benefit.

\[
tjr: This section is the only place where we mention a client may request a bare STH (with no proof).
We should include that up above somewhere, probably near "Proof Fetching"
\]

### Privacy in STH Interaction {#privacy-sth-interaction}

An HTTPS client may pollinate any STH within the last 14 days. An 
HTTPS Client may also pollinate an STH for any log that it knows about.
When a client pollinates STHs to a server, it will release more than one
STH at a time. It is unclear if a server may 'prime' a client and 
be able to reliably detect the client at a later time.

It's clear that a single site can track a user any way they wish, but this 
attack works cross-origin and is therefore more concerning. Two independent 
sites A and B want to collaborate to track a user cross-origin.  A feeds a 
client Carol some N specific STHs from the M logs Carol trusts, chosen to 
be older and less common, but still in the validity window.  Carol visits 
B and chooses to release some of the STHs she has stored, according to some 
policy.

Modeling a representation for how common older STHs are in the pools of 
clients, and examining that with a given policy of how to choose which 
of those STHs to send to B, it should be possible to calculate statistics 
about how unique Carol looks when talking to B and how useful/accurate 
such a tracking mechanism is.  

Building such a model is likely impossible without some real world data,
and requires a given implementation of a policy. To combat this attack,
suggestions are provided in {#pooling-policy-recommendations} to attempt to minimize it, but follow-up
testing with real world deployment to improvise the policy will be required.

### Trusted Auditors for HTTPS Clients {#privacy-trusted-auditors}

Some HTTPS clients may choose to use a trusted auditor. This trust
relationship leaks a large amount of information from the client to
the auditor. In particular, it will identify the web sites
that the client has visited to the auditor. Some clients may already
share this information to a third party, for example, when using a
server to synchronize browser history across devices in a
server-visible way, or when doing DNS lookups through a trusted DNS
resolver. For clients with such a relationship already established,
sending SCTs to a trusted auditor run by the same organization does not appear to leak
any additional information to the trusted third party.

Clients who wish to contact an auditor without associating their
identities with their SCTs may wish to use an anonymizing
network like Tor to submit SCT Feedback to the auditor. Auditors
SHOULD accept SCT Feedback that arrives over such anonymizing
networks.

Clients sending feedback to an auditor may prefer to reduce the
temporal granularity of the history leakage to the auditor by caching
and delaying their SCT Feedback reports. This elaborated upon in XXX Mixing.
This strategy is only as
effective as the granularity of the timestamps embedded in the SCTs
and STHs.

### HTTPS Clients as Auditors

Some HTTPS Clients may choose to act as Auditors themselves. A Client
taking on this role needs to consider the following:

- an Auditing HTTPS Client potentially leaks their history to the logs
  that they query. Querying the log through a cache or a proxy with
  many other users may avoid this leakage, but may leak information to
  the cache or proxy, in the same way that an non-Auditing HTTPS
  Client leaks information to a trusted auditor.

- an effective Auditor needs a strategy about what to do in the event
  that it discovers misbehavior from a log. Misbehavior from a log
  involves the log being unable to provide either (a) a consistency
  proof between two valid STHs or (b) an inclusion proof for a
  certificate to an STH any time after the log's MMD has elapsed from
  the issuance of the SCT. The log's inability to provide either proof
  will not be externally cryptographically-verifiable, as it may be
  indistinguishable from a network error.

# Policy Recommendations 

This section is intended as suggestions to implementors of HTTPS Clients,
HTTPS Servers, and Auditors. It is not a requirement for technique of 
implementation, so long as privacy considerations established above are obeyed.

## Mixing Recommendations {#pooling-policy-recommendations}

In several components of the CT Gossip ecosystem,
the recommendation is made that data from multiple sources be ingested, mixed, 
provided to a third party, stored for an indeterminate period of time, and 
eventually deleted.  The instances of these recommendations in this draft are:

- When a client receives SCTs during SCT Feedback, it should store the SCTs and Certificates for some amount of time, provide some of them back to the server at some point, and eventually remove them from its store
- When a client receives STHs during STH Pollination, it should store them for some amount of time, mix them with other STHs, release some of them them to various servers at some point, resolve some of them to new STHs, and eventually remove them from its store
- When a server receives SCTs during SCT Feedback, it should store them for some period of time, provide them to auditors some number of times, and may eventually remove them
- When a server receives STHs during STH Pollination, it should store them for some period of time, mix them with other STHs, provide some of them to connecting clients, may resolve them to new STHs via Proof Fetching, and eventually remove them from its store
- When a Trusted Auditor receives SCTs or historical STHs from clients, it should store them for some period of time, mix them with SCTs received from other clients, and act upon them at some period of time

Each of these instances have specific requirements for user privacy, and each have options that may not be invoked. As one example, a HTTPS client should not mix SCTs from server A with SCTs from server B and release server B's SCTs to Server A.  As another example, a HTTPS server may choose to resolve several STHs to a single more current STH via proof fetching, but it is under no obligation to do so.

These requirements should be met, but the general problem of aggregating multiple pieces of data, choosing when and how many to release, and when to remove is shared.  This problem has been previously been considered in the case of Mix Networks and Remailers, including papers such as [X], [Y], and [Z].

Certain common recommendations can be made:

- When choosing how many times to release data before expiring it from a cache, use a random number chosen from a distribution, rather than a fixed number. This prevents an adversary from knowing with certainty that it has successfully flushed a cache of a potentially incriminating piece of data.
\[
TODO:
 - Enumerating the problems of different types of mixes vs Cottrell Mix
 - Integrating the IP address into the algorithm for releasing data
 - Prefer aggregating multiple piece of data into a single STH when possible
 - The importance of Flushing Attacks, and tying in network connection, and time interval
]

## Blocking Recommendations {#blocking-policy-recommendations}

### Frustrating blocking {#blocking-policy-frustrating}

When making gossip connections to HTTPS Servers or Trusted Auditors, 
it is desirable to minimize the plaintext metadata in the connection
that can be used to identify the connection as a gossip connection
and therefore be of interest to block. Additionally, introducing some 
randomness into client behavior may be important - we assume that the 
adversary is able to inspect the behavior of the HTTPS client and 
understand how it makes gossip connections. 

As an example, if a client, after establishing a TLS connection (and 
receiving an SCT, but not making it's own HTTPS request yet), immediately 
opens a second TLS connection for the purpose of gossip - the adversary 
can reliably block this second connection to block gossip without 
affecting normal browsing.  For this reason it is recommended to 
run the gossip protocols over an existing connection to the server, 
making use of connection multiplexing such as HTTP Keep-Alives or SPDY.

Truncation is also a concern -if a client always establishes a TLS connection, 
makes a request, receives a response, and then always attempts a gossip 
communication immediately following the first response - truncation will
allow an attacker to block gossip reliably. 

### Responding to possible blocking {#blocking-policy-response}

\[
tjr: Not sure here.  Maybe this section will get folded up into the above.  
Or maybe it relates to the escape valve.
\]

# IANA considerations

TBD

# Contributors

The authors would like to thank the following contributors for
valuable suggestions: Al Cutter, Ben Laurie, Benjamin Kaduk, Karen
Seo, Magnus Ahltorp, Yan Zhu.

# ChangeLog

## Changes between ietf-00 and ietf-01

- STH Pollination Proof Fetching defined and indicated is optional
- Adding 3-Method Ecosystem section
- Handle cases with Logs cease operation
- Add a bit about tracking via STH Interaction
- Add a section with some early recommendations for mixing
- Add a section detailing blocking connections, frustrating it, and the implications

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
