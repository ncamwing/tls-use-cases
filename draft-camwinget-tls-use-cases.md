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
#  RFC3635:
#  RFC1573:
#  I-D.greevenbosch-appsawg-cbor-cddl: cddl
#  I-D.ietf-sacm-architecture-13:

informative:
#  RFC7632:
#  I-D.ietf-sacm-requirements: sacm-req

--- abstract

This is a placeholder:
This document describes use cases that describes the need for "TLS proxies".



--- middle

# Introduction

The current TLS 1.3 specification employs ephemeral techniques that prohibits the means for a "proxy" to be inserted to serve some scenarios.   This document describes some of the use cases to demonstrate the need for such a "proxy" capability.

## Requirements notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC
2119, BCP 14 {{RFC2119}}.

# TLS 1.3 Overview

Provide a high level overview of TLS 1.3 that highlights how a proxy becomes difficult.

## Use Case 1 - Acceptable Use Policy (AUP)

Enterprises deploy security devices to enforce Acceptable Use Policy (AUP) accroding to the IT and workplace policies.  The security devices, such as firewall/next-gen firewall and web proxy, act as middle boxes to scan traffic in the enterprise network for policy enforcement.

Sample AUP policies are:

"Employess are not allowed to access 'gaming' websites from enterprise network"

"Temporary workers are not allowed to use enterprise network to upload video clips to Internet, but are allowed to watch video clips"

Such enforcements are accomplished by controlling the DNS transactions and HTTP transactions.  A coase control is achieved by controlling the DNS response, however, in many cases, granular control is required at HTTP URL or Method levels, to distinguish a specific web page on a hosting site, or to differentiate between uploading and downloading operations.

The security device requires to access plain text HTTP header for granular AUP control.

## Use Case 2 - Malware and Threat Protection

Enterprises adopt a multi-technology approach when it comes to malware and threat protection for the network assets.  This include solutions deployed on the endpoint, network and cloud.

While endpoint application based solution is effective in protecting from malware and virus attecks, enterprises prefer to deploy multiple technologies for a multi-layer protection.  Network based solutions provide such additional protection with benefits including lower manangement costs.

The network based solutions comprise security devices and applications that scan network traffic for the purpose from malware signatures to 0-day analysis.  The security functions require access to clear text HTTP or other application level streams.

## Use Case 3 - Data Center Protection

## Use Case 4 - Application Operation over NAT



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
