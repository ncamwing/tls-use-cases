---
title: TLS Use Cases
docname: draft-camwinget-tls-use-cases
date: 2017-08-25

ipr: trust200902
area: security
wg: TLS
kw: Internet-Draft
cat: informational

coding: us-ascii
pi:
   toc: yes
   sortrefs: yes
   symrefs: yes
   comments: yes

author:
- ins: N. Cam-Winget
  name: Nancy Cam-Winget
  org: Cisco Systems
  email: ncamwing@cisco.com
  street: 3550 Cisco Way
  code: '95134'
  city: San Jose
  region: CA
  country: USA
- ins: E. Wang
  name: Eric Wang
  org: Cisco Systems
  email: ejwang@cisco.com
  street: 3550 Cisco Way
  code: '95134'
  city: San Jose
  region: CA
  country: USA
- ins: F. Andreasen
  name: Flemming Andreasen
  org: Cisco Systems
  email: fandreas@cisco.com
  street: 111 Wood Avenue South
  code: '08830'
  city: Iselin
  region: NJ
  country: USA

normative:
  RFC2119: 
  RFC5246: 
  I-D.ietf-tls-tls13

[comment]: 
	#  RFC3635: 
	#  RFC1573: 
	#  I-D.greevenbosch-appsawg-cbor-cddl: cddl 
	#  I-D.ietf-sacm-architecture-13:

informative:

[comment]: 
	# RFC7632: 
	# I-D.ietf-sacm-requirements: sacm-req

--- abstract

This is a placeholder:
This document describes use cases that describes the need for "TLS proxies".



--- middle

# Introduction

Network-based security solutions such as Firewalls (FW) and Intrusion Prevention Systems (IPS) rely on network traffic inspection to implement perimeter-based security policies. A significant portion of these security policies require clear-text traffic inspection above Layer 4, which becomes problematic when traffic is encrypted with Transport Layer Security (TLS) {{RFC5246}}. Today, network-based security solutions typically address this problem by becoming a man-in-the-middle (MITM) for the TLS session according to one of the following two scenarios:

1. Outbound Session, where the TLS session originates from inside the perimeter towards an entity on the outside
2. Inbound Session, where the TLS session originates from outside the perimeter towards an entity on the inside

For the outbound session scenario, a local root certificate and an accompanying (local) public/private key pair is generated. The local root certificate is installed on the inside entities for which TLS traffic is to be inspected, and the network security device(s) store a copy of the private key. During the TLS handshake, the network security device (hereafter referred to as a TLS proxy) modifies the certificate provided by the (outside) server and (re)signs it with the private key from the local root certificate. From here on, the TLS proxy has visibility into further exchanges between the client and server which enables it to to decrypt and inspect subsequent network traffic. 

For the Inbound session scenario, the TLS proxy is configured with a copy of the local servers' certificate(s) and corresponding private key(s). Based on the server certificate presented, the TLS proxy determines the corresponding private key, which again enables the TLS proxy to gain visibility into further exchanges between the client and server and hence decrypt subsequent network traffic. 

To date, there are a number of use case scenarios that rely on the above capabilities when used with TLS 1.2 {{RFC5246}} or earlier. TLS 1.3 {{I-D.ietf-tls-13}} introduces several changes which prevent a number of these use case scenarios from being satisfied with the types of TLS proxy based capabilities that exist today. 

It has been argued by some, that this should be viewed as a feature of TLS 1.3 and that the proper way of solving these issues is to rely on endpoint (client and server) based solutions instead. We believe this is an overly constrained view of the problem that ignores a number of important real-life use case scenarios. 

The purpose of this document is to provide a representative set of *network based security* use case scenarios that are negatively impacted by TLS 1.3 and do not lend themselves to an endpoint-based alternative solution. For each use case scenario, we highlight the specific aspect(s) of TLS 1.3 that makes the use case problematic with a TLS proxy based solution and we explain why an endpoint-based only solution is not considered acceptable. 

It should be noted that this document is looking only at *security* use cases with a focus on identifying the problematic ones. The document does not offer specific solutions to these; the goal is to stimulate further discussion and explore possible solutions subsequently.


## Requirements notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC
2119, BCP 14 {{RFC2119}}.

# TLS 1.3 Overview

*[Editor's Note: Provide a high level overview of TLS 1.3 that highlights how a proxy becomes difficult.]*


The current TLS 1.3 specification employs ephemeral techniques that prohibits the means for a "proxy" to be inserted to serve some scenarios.   This document describes some of the use cases to demonstrate the need for such a "proxy" capability.


# Inbound Session Use Cases


## Use Case I1 - Data Center Protection


## Use Case I2 - Application Operation over NAT


## Use Case I3 - Compliance



# Outbound Session Use Cases
*[Flemming: Do we actually have a problem with the outbound session use cases ?]*


## Use Case O1 - Acceptable Use Policy (AUP)

Enterprises deploy security devices to enforce Acceptable Use Policy (AUP) accroding to the IT and workplace policies.  The security devices, such as firewall/next-gen firewall and web proxy, act as middle boxes to scan traffic in the enterprise network for policy enforcement.

Sample AUP policies are:

"Employess are not allowed to access 'gaming' websites from enterprise network"

"Temporary workers are not allowed to use enterprise network to upload video clips to Internet, but are allowed to watch video clips"

Such enforcements are accomplished by controlling the DNS transactions and HTTP transactions.  A coase control is achieved by controlling the DNS response, however, in many cases, granular control is required at HTTP URL or Method levels, to distinguish a specific web page on a hosting site, or to differentiate between uploading and downloading operations.

The security device requires to access plain text HTTP header for granular AUP control.

*[Flemming: I think we need to clarify why you can't just do this at the endpoint instead]*

## Use Case O2 - Malware and Threat Protection

Enterprises adopt a multi-technology approach when it comes to malware and threat protection for the network assets.  This include solutions deployed on the endpoint, network and cloud.

While endpoint application based solution is effective in protecting from malware and virus attecks, enterprises prefer to deploy multiple technologies for a multi-layer protection.  Network based solutions provide such additional protection with benefits including lower manangement costs.

The network based solutions comprise security devices and applications that scan network traffic for the purpose from malware signatures to 0-day analysis.  The security functions require access to clear text HTTP or other application level streams.

*[Flemming: Again, I think it's key to explain why we can't just adopt an endpoint-based solution. I think the "lower management cost" is speculative].*


## Use Case O3 - IoT Endpoints
As the Internet of Everything continues to evolve, more and more endpoints become connected to the Internet. From a security point of view, some of the challenges presented by these are:

* Constrained devices with limited resources (CPU, memory, etc.)
* Lack of ability to install and update endpoint protection software.
* Lack of software updates as new vulnerabilities are discovered.



## Use Case O4 - Unpatched Endpoints
New vulnerabilities appear constantly and in spite of many advances in recent years in terms of automated software updates, especially in reaction to security vulnerabilities, the fact of the matter is that a very large number of endpoints continue to run versions of software with known vulnerabilities. 

In theory, these endpoints should of course be patched, but in practice, it is often not done which leaves the endpoint open to the vulnerability in question. A network-based security solution can look for attempted exploits of such vulnerabilities and stop them before they reach the unpatched endpoint. 


## Use Case O5 - Rapid Containment of New Vulnerability and Campaigns
When a new vulnerability is discovered or an attack campaign is launched, it is important to patch the vulnerability or contain the campaign as quickly as possible. Patches however are not always available immediately, and even when they are, most endpoints are in practice not patched immediately, which leaves them open to the attack. 

A network-based security solution can look for attempted exploits of such new vulnerabilities or recognize an attack being launched based on security intelligence related to the campaign and stop them before they reach the vulnerable endpoint. 


## Use Case O6 - End-of-Life Endpoint
Older endpoints (and in some cases even new ones) will not receive any software updates. As new vulnerabilities inevitably are discovered, these endpoints will be vulnerable to exploits. 

A network-based security solution can help prevent such exploits.


## Use Case O7 - Compliance







#  IANA considerations

This document does not include IANA considerations.

#  Security Considerations

TBD

#  Acknowledgements

TBD

#  Change Log

First version -00

# Contributors

--- back
