---
stand_alone: true
ipr: trust200902
docname: draft-ietf-teep-protocol-latest
cat: std
submissiontype: IETF
pi:
  strict: 'yes'
  toc: 'yes'
  tocdepth: '4'
  symrefs: 'yes'
  sortrefs: 'yes'
  compact: 'yes'
  subcompact: 'no'
title: Trusted Execution Environment Provisioning (TEEP) Protocol
abbrev: TEEP Protocol
area: Security
wg: TEEP
kw: Trusted Execution Environment
date: 2023
author:

 -
  ins: H. Tschofenig
  name: Hannes Tschofenig
  org: ''
  street: ''
  city: ''
  region: ''
  code: ''
  country: Austria
  email: hannes.tschofenig@gmx.net

 -
  ins: M. Pei
  name: Mingliang Pei
  org: Broadcom
  street: ''
  city: ''
  region: ''
  code: ''
  country: US
  email: mingliang.pei@broadcom.com

 -
  ins: D. Wheeler
  name: David Wheeler
  org: Amazon
  street: ''
  city: ''
  region: ''
  code: ''
  country: US
  email: davewhee@amazon.com

 -
  ins: D. Thaler
  name: Dave Thaler
  org: Microsoft
  street: ''
  city: ''
  region: ''
  code: ''
  country: US
  email: dthaler@microsoft.com

 -
  ins: A. Tsukamoto
  name: Akira Tsukamoto
  org: ''
  street: ''
  city: ''
  region: ''
  code: ''
  country: JP
  email: akira.tsukamoto@gmail.com

normative:
  RFC9052:
  RFC3629:
  RFC5198:
  RFC8747:
  RFC8949:
  RFC9052:
  RFC9334:
  I-D.ietf-rats-eat:
  I-D.ietf-rats-reference-interaction-models:
  I-D.ietf-suit-manifest:
  I-D.ietf-suit-mti:
  I-D.ietf-suit-trust-domains:
  I-D.ietf-suit-report:
  COSE.Algorithm:
    title: "COSE Algorithms"
    author:
      org: IANA
    target: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
informative:
  I-D.ietf-suit-firmware-encryption: 
  I-D.ietf-rats-ar4si:
  I-D.ietf-teep-architecture: 
  I-D.ietf-rats-eat-media-type:
  I-D.ietf-rats-concise-ta-stores:
  RFC8610: 
  RFC8915:
  RFC5934:

--- abstract


This document specifies a protocol that installs, updates, and deletes
Trusted Components in a device with a Trusted Execution
Environment (TEE).  This specification defines an interoperable
protocol for managing the lifecycle of Trusted Components.

--- middle

# Introduction {#introduction}

The Trusted Execution Environment (TEE) concept has been designed to
separate a regular operating system, also referred as a Rich Execution
Environment (REE), from security-sensitive applications. In a TEE
ecosystem, device vendors may use different operating systems in the
REE and may use different types of TEEs. When Trusted Component Developers or
Device Administrators use Trusted Application Managers (TAMs) to
install, update, and delete Trusted Applications and their dependencies on a wide range
of devices with potentially different TEEs then an interoperability
need arises.

This document specifies the protocol for communicating between a TAM
and a TEEP Agent.

The Trusted Execution Environment Provisioning (TEEP) architecture
document {{I-D.ietf-teep-architecture}} provides design
guidance and introduces the
necessary terminology.


# Terminology

{::boilerplate bcp14}

This specification re-uses the terminology defined in {{I-D.ietf-teep-architecture}}.

As explained in Section 4.4 of that document, the TEEP protocol treats
each Trusted Application (TA), any dependencies the TA has, and personalization data as separate
components that are expressed in SUIT manifests, and a SUIT manifest
might contain or reference multiple binaries (see {{I-D.ietf-suit-manifest}}
for more details).

As such, the term Trusted Component (TC) in this document refers to a
set of binaries expressed in a SUIT manifest, to be installed in
a TEE.  Note that a Trusted Component may include one or more TAs
and/or configuration data and keys needed by a TA to operate correctly.

Each Trusted Component is uniquely identified by a SUIT Component Identifier
(see {{I-D.ietf-suit-manifest}} Section 8.7.2.2).

Attestation related terms, such as Evidence and Attestation Results,
are as defined in {{RFC9334}}.

# Message Overview {#messages}

The TEEP protocol consists of messages exchanged between a TAM
and a TEEP Agent.
The messages are encoded in CBOR and designed to provide end-to-end security.
TEEP protocol messages are signed by the endpoints, i.e., the TAM and the
TEEP Agent, but Trusted
Applications may also be encrypted and signed by a Trusted Component Developer or
Device Administrator.
The TEEP protocol not only uses
CBOR but also the respective security wrapper, namely COSE {{RFC9052}}. Furthermore, for software updates the SUIT
manifest format {{I-D.ietf-suit-manifest}} is used, and
for attestation the Entity Attestation Token (EAT) {{I-D.ietf-rats-eat}}
format is supported although other attestation formats are also permitted.

This specification defines five messages: QueryRequest, QueryResponse,
Update, Success, and Error.

A TAM queries a device's current state with a QueryRequest message.
A TEEP Agent will, after authenticating and authorizing the request, report
attestation information, list all Trusted Components, and provide information about supported
algorithms and extensions in a QueryResponse message. An error message is
returned if the request
could not be processed. A TAM will process the QueryResponse message and
determine
whether to initiate subsequent message exchanges to install, update, or delete Trusted
Applications.

~~~~
  +------------+           +-------------+
  | TAM        |           |TEEP Agent   |
  +------------+           +-------------+

    QueryRequest ------->

                           QueryResponse

                 <-------     or

                             Error
~~~~


With the Update message a TAM can instruct a TEEP Agent to install and/or
delete one or more Trusted Components.
The TEEP Agent will process the message, determine whether the TAM is authorized
and whether the
Trusted Component has been signed by an authorized Trusted Component Signer.
A Success message is returned when the operation has been completed successfully,
or an Error message
otherwise.

~~~~
 +------------+           +-------------+
 | TAM        |           |TEEP Agent   |
 +------------+           +-------------+

             Update  ---->

                            Success

                    <----    or

                            Error
~~~~

# Detailed Messages Specification {#detailmsg}

TEEP messages are protected by the COSE_Sign1 or COSE_Sign structure as described in {{teep-ciphersuite}}.
The TEEP protocol messages are described in CDDL format {{RFC8610}} below.

~~~~ cddl-teep-message
teep-message = $teep-message-type .within teep-message-framework

teep-message-framework = [
  type: $teep-type / $teep-type-extension,
  options: { * teep-option },
  * any; further elements, e.g., for data-item-requested
]

teep-option = (uint => any)

; messages defined below:
$teep-message-type /= query-request
$teep-message-type /= query-response
$teep-message-type /= update
$teep-message-type /= teep-success
$teep-message-type /= teep-error

; message type numbers, in one byte which could take a number from 0 to 23
$teep-type = (0..23)
TEEP-TYPE-query-request = 1
TEEP-TYPE-query-response = 2
TEEP-TYPE-update = 3
TEEP-TYPE-teep-success = 5
TEEP-TYPE-teep-error = 6
~~~~

## Creating and Validating TEEP Messages

### Creating a TEEP message

To create a TEEP message, the following steps are performed.

1. Create a TEEP message according to the description below and populate
  it with the respective content.  TEEP messages sent by TAMs (QueryRequest
  and Update) can include a "token".
  The TAM can decide, in any implementation-specific way, whether to include a token
  in a message.  The first usage of a token
  generated by a TAM MUST be randomly created.
  Subsequent token values MUST be different for each subsequent message
  created by a TAM.

1. Create a COSE Header containing the desired set of Header
  Parameters.  The COSE Header MUST be valid per the {{RFC9052}} specification.

1. Create a COSE_Sign1 or COSE_Sign object
  using the TEEP message as the COSE_Sign1 or COSE_Sign Payload; all
  steps specified in {{RFC9052}} for creating a
  COSE_Sign1 or COSE_Sign object MUST be followed.

### Validating a TEEP Message {#validation}

When TEEP message is received (see the ProcessTeepMessage conceptual API
defined in {{I-D.ietf-teep-architecture}} section 6.2.1),
the following validation steps are performed. If any of
the listed steps fail, then the TEEP message MUST be rejected.

1. Verify that the received message is a valid CBOR object.

1. Verify that the message contains a COSE_Sign1 or COSE_Sign structure.

1. Verify that the resulting COSE Header includes only parameters
  and values whose syntax and semantics are both understood and
  supported or that are specified as being ignored when not
  understood.

1. Follow the steps specified in Section 4 of {{RFC9052}} ("Signing Objects") for
  validating a COSE_Sign1 or COSE_Sign object. The COSE_Sign1 or COSE_Sign payload is the content
  of the TEEP message.

1. Verify that the TEEP message is a valid CBOR map and verify the fields of
  the
  TEEP message according to this specification.




## QueryRequest Message


A QueryRequest message is used by the TAM to learn
information from the TEEP Agent, such as
the features supported by the TEEP Agent, including
cipher suites and protocol versions. Additionally,
the TAM can selectively request data items from the
TEEP Agent via the request parameter. Currently,
the following features are supported:

 - Request for attestation information,
 - Listing supported extensions,
 - Querying installed Trusted Components, and
 - Request for logging information in SUIT Reports.

Like other TEEP messages, the QueryRequest message is
signed, and the relevant CDDL snippet is shown below.
The complete CDDL structure is shown in Appendix C.

~~~~ cddl-query-request
query-request = [
  type: TEEP-TYPE-query-request,
  options: {
    ? token => bstr .size (8..64),
    ? supported-freshness-mechanisms => [ + $freshness-mechanism ],
    ? challenge-agent => bstr .size (8..512),
    ? versions => [ + version ],
    ? attestation-payload-format => text,
    ? attestation-payload => bstr,
    ? suit-reports => [ + bstr ],
    * $$query-request-extensions,
    * $$teep-option-extensions
  },
  supported-teep-cipher-suites: [ + $teep-cipher-suite ],
  supported-suit-cose-profiles: [ + $suit-cose-profile ],
  data-item-requested: uint .bits data-item-requested
]

version = uint .size 4
ext-info = uint .size 4

; data items as bitmaps
data-item-requested = &(
  attestation: 0,
  trusted-components: 1,
  extensions: 2,
  suit-reports: 3,
)
~~~~

The message has the following fields:

{: vspace='0'}
type
: The value of (1) corresponds to a QueryRequest message sent from the TAM to
  the TEEP Agent.

token
: The value in the token parameter is used to match responses to requests,
  such as to look up any implementation-specific state it might have saved about
  that request, or to ignore responses to older QueryRequest messages before
  some configuration changes were made that affected their content.
  This is particularly useful when a TAM issues multiple concurrent requests
  to a TEEP Agent. The token MUST be present if and only if the attestation bit is clear in
  the data-item-requested value. The size of the token is at least 8 bytes
  (64 bits) and maximum of 64 bytes, which is the same as in an EAT Nonce
  Claim (see {{I-D.ietf-rats-eat}} Section 3.3). The first usage of a token
  generated by a TAM MUST be randomly created.
  Subsequent token values MUST be different for each request message
  to distinguish the correct response from multiple requests.
  The token value MUST NOT be used for other purposes, such as a TAM to
  identify the devices and/or a device to identify TAMs or Trusted Components.
  The TAM SHOULD set an expiration time for each token and MUST ignore any messages with expired tokens.
  The TAM MUST expire the token value after receiving the first response
  containing the token value and ignore any subsequent messages that have the same token
  value.

supported-teep-cipher-suites
: The supported-teep-cipher-suites parameter lists the TEEP cipher suites
  supported by the TAM. Details
  about the cipher suite encoding can be found in {{teep-ciphersuite}}.

supported-suit-cose-profiles
: The supported-suit-cose-profiles parameter lists the SUIT profiles
  supported by the TAM. Details
  about the cipher suite encoding can be found in {{eat-suit-ciphersuite}}.

data-item-requested
: The data-item-requested parameter indicates what information the TAM requests from the TEEP
  Agent in the form of a bitmap.

   attestation (1)
   : With this value the TAM requests the TEEP Agent to return an attestation payload,
     whether Evidence (e.g., an EAT) or an Attestation Result, in the response.

   trusted-components (2)
   : With this value the TAM queries the TEEP Agent for all installed Trusted Components.

   extensions (4)
   : With this value the TAM queries the TEEP Agent for supported capabilities
     and extensions, which allows a TAM to discover the capabilities of a TEEP
     Agent implementation.

   suit-reports (8)
   : With this value the TAM requests the TEEP Agent to return SUIT Reports
     in the response.

   Further values may be added in the future.

supported-freshness-mechanisms
: The supported-freshness-mechanisms parameter lists the freshness mechanism(s) supported by the TAM.
  Details about the encoding can be found in {{freshness-mechanisms}}.
  If this parameter is absent, it means only the nonce mechanism is supported.
  It MUST be absent if the attestation bit is clear.

challenge-agent
: The challenge-agent field is an optional parameter used for ensuring the freshness of
  attestation evidence returned with a QueryResponse message. It MUST be absent if
  the attestation bit is clear or the Passport model is used (since the token is used instead in those cases).
  When a challenge-agent is
  provided in the QueryRequest and Evidence in the form of an EAT is returned with a QueryResponse message
  then the challenge-agent contained in this request MUST be used to generate the EAT,
  by copying the challenge-agent into the eat_nonce in the EAT profile {{eat}} if
  using the Nonce freshness mechanism.  For more details see {{freshness-mechanisms}}.

  If any format other than EAT is used, it is up to that
  format to define the use of the challenge-agent field.

versions
: The versions parameter enumerates the TEEP protocol version(s) supported by the TAM.
  A value of 0 refers to the current version of the TEEP protocol.
  If this field is not present, it is to be treated the same as if
  it contained only version 0.

attestation-payload-format
: The attestation-payload-format parameter indicates the IANA Media Type of the
  attestation-payload parameter, where media type parameters are permitted after
  the media type.  For protocol version 0, the absence of this parameter indicates that
  the format is "application/eat+cwt; eat_profile=https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-12" (see {{I-D.ietf-rats-eat-media-type}}
  for further discussion).
  (RFC-editor: upon RFC publication, replace URI above with
  "https://www.rfc-editor.org/info/rfcXXXX" where XXXX is the RFC number
  of this document.)
  It MUST be present if the attestation-payload parameter
  is present and the format is not an EAT in CWT format with the profile
  defined below in {{eat}}.

attestation-payload
: The attestation-payload parameter contains Evidence or an Attestation Result
  of the TAM for the TEEP Agent to perform attestation of the TAM.
  If the attestation-payload-format parameter is absent,
  the attestation payload contained in this parameter MUST be
  an Entity Attestation Token following the encoding
  defined in {{I-D.ietf-rats-eat}}.  See {{attestation}} for further discussion.

suit-reports
: If present, the suit-reports parameter contains a set of "boot" (including
  starting an executable in an OS context) time SUIT Reports of the TAM
  as defined by SUIT_Report in Section 4 of {{I-D.ietf-suit-report}},
  encoded using COSE as discussed in {{eat-suit-ciphersuite}}.
  SUIT Reports can be useful in QueryRequest messages to
  pass information to the TEEP Agent without depending on a Verifier including
  the relevant information in Attestation Results.

## QueryResponse Message {#query-response}

The QueryResponse message is the successful response by the TEEP Agent after
receiving a QueryRequest message.  As discussed in {{agent}}, it can also be sent
unsolicited if the contents of the QueryRequest are already known and do not vary
per message.

Like other TEEP messages, the QueryResponse message is
signed, and the relevant CDDL snippet is shown below.
The complete CDDL structure is shown in Appendix C.

~~~~ cddl-query-response
query-response = [
  type: TEEP-TYPE-query-response,
  options: {
    ? token => bstr .size (8..64),
    ? selected-teep-cipher-suite => $teep-cipher-suite,
    ? selected-version => version,
    ? attestation-payload-format => text,
    ? attestation-payload => bstr,
    ? suit-reports => [ + bstr ],
    ? tc-list => [ + system-property-claims ],
    ? requested-tc-list => [ + requested-tc-info ],
    ? unneeded-manifest-list => [ + SUIT_Component_Identifier ],
    ? ext-list => [ + ext-info ],
    * $$query-response-extensions,
    * $$teep-option-extensions
  }
]

requested-tc-info = {
  component-id => SUIT_Component_Identifier,
  ? tc-manifest-sequence-number => uint .size 8,
  ? have-binary => bool
}
~~~~

The QueryResponse message has the following fields:

{: vspace='0'}

type
: The value of (2) corresponds to a QueryResponse message sent from the TEEP Agent
  to the TAM.

token
: The value in the token parameter is used to match responses to requests. The
  value MUST correspond to the value received with the QueryRequest message
  if one was present, and MUST be absent if no token was present in the
  QueryRequest.

selected-teep-cipher-suite
: The selected-teep-cipher-suite parameter indicates the selected TEEP cipher suite. If this
  parameter is not present, it is to be treated as if the TEEP Agent accepts
  any TEEP cipher suites listed in the QueryRequest, so the TAM can select one.
  Details about the TEEP cipher suite encoding can be found in {{teep-ciphersuite}}.

selected-version
: The selected-version parameter indicates the TEEP protocol version selected by the
  TEEP Agent. The absence of this parameter indicates the same as if it
  was present with a value of 0.

attestation-payload-format
: The attestation-payload-format parameter indicates the IANA Media Type of the
  attestation-payload parameter, where media type parameters are permitted after
  the media type.  For protocol version 0, the absence of this parameter indicates that
  the format is "application/eat+cwt; eat_profile=https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-12" (see {{I-D.ietf-rats-eat-media-type}}
  for further discussion).
  (RFC-editor: upon RFC publication, replace URI above with
  "https://www.rfc-editor.org/info/rfcXXXX" where XXXX is the RFC number
  of this document.)
  It MUST be present if the attestation-payload parameter
  is present and the format is not an EAT in CWT format with the profile
  defined below in {{eat}}.

attestation-payload
: The attestation-payload parameter contains Evidence or an Attestation Result.  This parameter
  MUST be present if the QueryResponse is sent in response to a QueryRequest
  with the attestation bit set.  If the attestation-payload-format parameter is absent,
  the attestation payload contained in this parameter MUST be
  an Entity Attestation Token following the encoding
  defined in {{I-D.ietf-rats-eat}}.  See {{attestation}} for further discussion.

suit-reports
: If present, the suit-reports parameter contains a set of "boot" (including
  starting an executable in an OS context) time SUIT Reports
  as defined by SUIT_Report in Section 4 of {{I-D.ietf-suit-report}},
  encoded using COSE as discussed in {{eat-suit-ciphersuite}}.
  If a token parameter was present in the QueryRequest
  message the QueryResponse message is in response to,
  the suit-report-nonce field MUST be present in the SUIT Report with a
  value matching the token parameter in the QueryRequest
  message.  SUIT Reports can be useful in QueryResponse messages to
  pass information to the TAM without depending on a Verifier including
  the relevant information in Attestation Results.

tc-list
: The tc-list parameter enumerates the Trusted Components installed on the device
  in the form of system-property-claims objects, as defined in Section 4 of {{I-D.ietf-suit-report}}. The system-property-claims can
  be used to learn device identifying information and TEE identifying information
  for distinguishing which Trusted Components to install in the TEE.
  This parameter MUST be present if the
  QueryResponse is sent in response to a QueryRequest with the
  trusted-components bit set.

requested-tc-list
: The requested-tc-list parameter enumerates the Trusted Components that are
  not currently installed in the TEE, but which are requested to be installed,
  for example by an installer of an Untrusted Application that has a TA
  as a dependency, or by a Trusted Application that has another Trusted
  Component as a dependency.  Requested Trusted Components are expressed in
  the form of requested-tc-info objects.
  A TEEP Agent can get this information from the RequestTA conceptual API
  defined in {{I-D.ietf-teep-architecture}} section 6.2.1.

unneeded-manifest-list
: The unneeded-manifest-list parameter enumerates the SUIT manifests whose components are
  currently installed in the TEE, but which are no longer needed by any
  other application.  The TAM can use this information in determining
  whether a SUIT manifest can be unlinked.  Each unneeded SUIT manifest is identified
  by its SUIT Manifest Component ID (note that this is the Component ID for the manifest
  itself, which is different from the Component ID of a component installed by the manifest,
  see {{I-D.ietf-suit-trust-domains}} for more discussion).
  A TEEP Agent can get this information from the UnrequestTA conceptual API
  defined in {{I-D.ietf-teep-architecture}} section 6.2.1.

ext-list
: The ext-list parameter lists the supported extensions. This document does not
  define any extensions.  This parameter MUST be present if the
  QueryResponse is sent in response to a QueryRequest with the
  extensions bit set.

The requested-tc-info message has the following fields:

{: vspace='0'}

component-id
: A SUIT Component Identifier.

tc-manifest-sequence-number
: The minimum suit-manifest-sequence-number value from a SUIT manifest for
  the Trusted Component.  If not present, indicates that any sequence number will do.

have-binary
: If present with a value of true, indicates that the TEEP Agent already has
  the Trusted Component binary and only needs an Update message with a SUIT manifest
  that authorizes installing it.  If have-binary is true, the
  tc-manifest-sequence-number field MUST be present.

### Evidence and Attestation Results {#attestation}

Section 7 of {{I-D.ietf-teep-architecture}} lists information that may appear
in Evidence depending on the circumstance.  However, the Evidence is
opaque to the TEEP protocol and there are no formal requirements on the contents
of Evidence.

TAMs however consume Attestation Results and do need enough information therein to
make decisions on how to remediate a TEE that is out of compliance, or update a TEE
that is requesting an authorized change.  To do so, the information in
Section 7 of {{I-D.ietf-teep-architecture}} is often required depending on the policy.

Attestation Results SHOULD use Entity Attestation Tokens (EATs).  Use of any other
format, such as a widely implemented format for a specific processor vendor, is
permitted but increases the complexity of the TAM by requiring it to understand
the format for each such format rather than only the common EAT format so is not
recommended.

When an EAT is used, the following claims can be used to meet those
requirements, whether these claims appear in Attestation Results, or in Evidence
for the Verifier to use when generating Attestation Results of some form:

| Requirement  | Claim | Reference |
| Freshness proof | nonce | Section 4.1 of {{I-D.ietf-rats-eat}} |
| Device unique identifier | ueid | Section 4.2.1 of {{I-D.ietf-rats-eat}} |
| Vendor of the device | oemid | Section 4.2.3 of {{I-D.ietf-rats-eat}} |
| Class of the device | hwmodel | Section 4.2.4 of {{I-D.ietf-rats-eat}} |
| TEE hardware type | hwversion | Section 4.2.5 of {{I-D.ietf-rats-eat}} |
| TEE hardware version | hwversion | Section 4.2.5 of {{I-D.ietf-rats-eat}} |
| TEE firmware type | manifests | Section 4.2.15 of {{I-D.ietf-rats-eat}} |
| TEE firmware version | manifests | Section 4.2.15 of {{I-D.ietf-rats-eat}} |

The "manifests" claim should include information about the TEEP Agent as well
as any of its dependencies such as firmware.

## Update Message {#update-msg-def}

The Update message is used by the TAM to install and/or delete one or more Trusted
Components via the TEEP Agent.  It can also be used to pass a successful
Attestation Report back to the TEEP Agent when the TAM is configured as
an intermediary between the TEEP Agent and a Verifier, as shown in the figure
below, where the Attestation Result passed back to the Attester can be used
as a so-called "passport" (see section 5.1 of {{RFC9334}})
that can be presented to other Relying Parties.

~~~~
         +---------------+
         |   Verifier    |
         +---------------+
               ^    | Attestation
      Evidence |    v   Result
         +---------------+
         |     TAM /     |
         | Relying Party |
         +---------------+
 QueryResponse ^    |    Update
   (Evidence)  |    | (Attestation
               |    v    Result)
         +---------------+             +---------------+
         |  TEEP Agent   |------------>|     Other     |
         |  / Attester   | Attestation | Relying Party |
         +---------------+    Result   +---------------+

    Figure 1: Example use of TEEP and attestation
~~~~

Like other TEEP messages, the Update message is
signed, and the relevant CDDL snippet is shown below.
The complete CDDL structure is shown in Appendix C.

~~~~ cddl-update
update = [
  type: TEEP-TYPE-update,
  options: {
    ? token => bstr .size (8..64),
    ? unneeded-manifest-list => [ + SUIT_Component_Identifier ],
    ? manifest-list => [ + bstr .cbor SUIT_Envelope ],
    ? attestation-payload-format => text,
    ? attestation-payload => bstr,
    ? err-code => (0..23),
    ? err-msg => text .size (1..128),
    * $$update-extensions,
    * $$teep-option-extensions
  }
]
~~~~

The Update message has the following fields:

{: vspace='0'}
type
: The value of (3) corresponds to an Update message sent from the TAM to
  the TEEP Agent. In case of successful processing, a Success
  message is returned by the TEEP Agent. In case of an error, an Error message
  is returned. Note that the Update message
  is used for initial Trusted Component installation as well as for updates
  and deletes.

token
: The value in the token field is used to match responses to requests.

unneeded-manifest-list
: The unneeded-manifest-list parameter enumerates the SUIT manifests to be unlinked.
  Each unneeded SUIT manifest is identified by its SUIT Manifest Component ID.
  The SUIT manifest processor MAY execute uninstall section in the manifest.

manifest-list
: The manifest-list field is used to convey one or multiple SUIT manifests
  to install.  A manifest is
  a bundle of metadata about a Trusted Component, such as where to
  find the code, the devices to which it applies, and cryptographic
  information protecting the manifest. The manifest may also convey personalization
  data. Trusted Component binaries and personalization data can be signed and encrypted
  by the same Trusted Component Signer. Other combinations are, however, possible as well. For example,
  it is also possible for the TAM to sign and encrypt the personalization data
  and to let the Trusted Component Developer sign and/or encrypt the Trusted Component binary.

attestation-payload-format
: The attestation-payload-format parameter indicates the IANA Media Type of the
  attestation-payload parameter, where media type parameters are permitted after
  the media type.  The absence of this parameter indicates that
  the format is "application/eat+cwt; eat_profile=https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-12" (see {{I-D.ietf-rats-eat-media-type}}
  for further discussion).
  (RFC-editor: upon RFC publication, replace URI above with
  "https://www.rfc-editor.org/info/rfcXXXX" where XXXX is the RFC number
  of this document.)
  It MUST be present if the attestation-payload parameter
  is present and the format is not an EAT in CWT format with the profile
  defined below in {{eat}}.

attestation-payload
: The attestation-payload parameter contains an Attestation Result.  This parameter
  If the attestation-payload-format parameter is absent,
  the attestation payload contained in this parameter MUST be
  an Entity Attestation Token following the encoding
  defined in {{I-D.ietf-rats-eat}}.  See {{attestation}} for further discussion.

err-code
: The err-code parameter contains one of the error codes listed in the
  {{error-message-def}}, which describes the reasons for the error when
  performing QueryResponse in the TAM.

err-msg
: The err-msg parameter is human-readable diagnostic text that MUST be encoded
  using UTF-8 {{RFC3629}} in Net-Unicode format {{RFC5198}} with a maximum of 128 bytes.

Note that an Update message carrying one or more SUIT manifests will inherently
involve multiple signatures, one by the TAM in the TEEP message and one from
a Trusted Component Signer inside each manifest.  This is intentional as they
are for different purposes.

The TAM is what authorizes
apps to be installed, updated, and deleted on a given TEE and so the TEEP
signature is checked by the TEEP Agent at protocol message processing time.
(This same TEEP security wrapper is also used on messages like QueryRequest
so that Agents only send potentially sensitive data such as Evidence to
trusted TAMs.)

The Trusted Component signer on the other hand is what authorizes the
Trusted Component to actually run, so the manifest signature could be
checked at install time or load (or run) time or both, and this checking is
done by the TEE independent of whether TEEP is used or some other update
mechanism.
See section 5 of {{I-D.ietf-teep-architecture}} for further discussion.


The Update Message has a SUIT_Envelope containing SUIT manifests. Following are some example scenarios using SUIT manifests in the Update Message.

### Scenario 1: Having one SUIT Manifest pointing to a URI of a Trusted Component Binary {#directtam}

In this scenario, a SUIT Manifest has a URI pointing to a Trusted Component Binary.

A Trusted Component Developer creates a new Trusted Component Binary and hosts it at a Trusted Component Developer's URI.  Then the Trusted Component Developer generates an associated SUIT manifest with the filename "tc-uuid.suit" that contains the URI. The filename "tc-uuid.suit" is used in Scenario 3 later.

The TAM receives the latest SUIT manifest from the Trusted Component Developer, and
the URI it contains will not be changeable by the TAM since the SUIT manifest is signed by the Trusted Component Developer.


Pros:

 - The Trusted Component Developer can ensure that the intact Trusted Component Binary is downloaded by devices
 - The TAM does not have to send large Update messages containing the Trusted Component Binary

Cons:

 - The Trusted Component Developer must host the Trusted Component Binary server
 - The device must fetch the Trusted Component Binary in another connection after receiving an Update message
 - A device's IP address and therefore location may be revealed to the Trusted Component Binary server

~~~~
    +------------+           +-------------+
    | TAM        |           | TEEP Agent  |
    +------------+           +-------------+

             Update  ---->

    +=================== teep-protocol(TAM) ==================+
    | TEEP_Message([                                          |
    |   TEEP-TYPE-update,                                     |
    |   options: {                                            |
    |     manifest-list: [                                    |
    |       += suit-manifest "tc-uuid.suit" (TC Developer) =+ |
    |       | SUIT_Envelope({                               | |
    |       |   manifest: {                                 | |
    |       |     install: {                                | |
    |       |       override-parameters: {                  | |
    |       |         uri: "https://example.org/tc-uuid.ta" | |
    |       |       },                                      | |
    |       |       fetch                                   | |
    |       |     }                                         | |
    |       |   }                                           | |
    |       | })                                            | |
    |       +===============================================+ |
    |     ]                                                   |
    |   }                                                     |
    | ])                                                      |
    +=========================================================+

    and then,

    +-------------+          +--------------+
    | TEEP Agent  |          | TC Developer |
    +-------------+          +--------------+

                     <----

      fetch "https://example.org/tc-uuid.ta"

          +======= tc-uuid.ta =======+
          | 48 65 6C 6C 6F 2C 20 ... |
          +==========================+

    Figure 2: URI of the Trusted Component Binary
~~~~

For the full SUIT Manifest example binary, see {{suit-uri}}.

### Scenario 2: Having a SUIT Manifest include the Trusted Component Binary

In this scenario, the SUIT manifest contains the entire Trusted Component Binary as an integrated payload (see {{I-D.ietf-suit-manifest}} Section 7.5).

A Trusted Component Developer delegates the task of delivering the Trusted Component Binary to the TAM inside the SUIT manifest. The Trusted Component Developer creates a SUIT manifest and embeds the Trusted Component Binary, which is referenced in the suit-integrated-payload element containing the fragment-only reference "#tc", in the envelope. The Trusted Component Developer transmits the entire bundle to the TAM.

The TAM serves the SUIT manifest containing the Trusted Component Binary to the device in an Update message.

Pros:

 - The device can obtain the Trusted Component Binary and the SUIT manifest in one Update message.
 - The Trusted Component Developer does not have to host a server to deliver the Trusted Component Binary to devices.

Cons:

 - The TAM must host the Trusted Component Binary rather than delegating storage to the Trusted Component Developer.
 - The TAM must deliver Trusted Component Binaries in Update messages, which increases the size of the Update message.

~~~~
    +------------+           +-------------+
    | TAM        |           | TEEP Agent  |
    +------------+           +-------------+

             Update  ---->

      +=========== teep-protocol(TAM) ============+
      | TEEP_Message([                            |
      |   TEEP-TYPE-update,                       |
      |   options: {                              |
      |     manifest-list: [                      |
      |       +== suit-manifest(TC Developer) ==+ |
      |       | SUIT_Envelope({                 | |
      |       |   manifest: {                   | |
      |       |     install: {                  | |
      |       |       override-parameters: {    | |
      |       |         uri: "#tc"              | |
      |       |       },                        | |
      |       |       fetch                     | |
      |       |     }                           | |
      |       |   },                            | |
      |       |   "#tc": h'48 65 6C 6C ...'     | |
      |       | })                              | |
      |       +=================================+ |
      |     ]                                     |
      |   }                                       |
      | ])                                        |
      +===========================================+

    Figure 3: Integrated Payload with Trusted Component Binary
~~~~

For the full SUIT Manifest example binary, see {{suit-integrated}}.


### Scenario 3: Supplying Personalization Data for the Trusted Component Binary

In this scenario, Personalization Data is associated with the Trusted Component Binary "tc-uuid.suit" from Scenario 1.

The Trusted Component Developer places encrypted Personalization Data in the SUIT manifest, and it will be delivered by the TAM.
The SUIT manifest processor decrypts it and then store it into file named "config.json", and then install the dependency component.

The TAM delivers the SUIT manifest of the Personalization Data which depends on the Trusted Component Binary from Scenario 1.

~~~~
    +------------+           +-------------+
    | TAM        |           | TEEP Agent  |
    +------------+           +-------------+

             Update  ---->

      +================== teep-protocol(TAM) ======================+
      | TEEP_Message([                                             |
      |   TEEP-TYPE-update,                                        |
      |   options: {                                               |
      |     manifest-list: [                                       |
      |       +========= suit-manifest(TC Developer) ============+ |
      |       | SUIT_Envelope({                                  | |
      |       |   manifest: {                                    | |
      |       |     common: {                                    | |
      |       |       dependencies: {                            | |
      |       |         dependency-prefix 1: {                   | |
      |       |           [tc-uuid, 'suit']                      | |
      |       |         }                                        | |
      |       |       }                                          | |
      |       |       components: [                              | |
      |       |         ['config.json']                          | |
      |       |       ]                                          | |
      |       |     },                                           | |
      |       |     dependency-resolution: {                     | |
      |       |       override-parameters: {                     | |
      |       |         uri: "https://example.org/tc-uuid.suit"  | |
      |       |       },                                         | |
      |       |       fetch                                      | |
      |       |     },                                           | |
      |       |     install: {                                   | |
      |       |       set-component-index 0,                     | |
      |       |       override-parameters: {                     | |
      |       |         content: h'48FE0794...'                  | |
      |       |         encryption-info: << ... >>               | |
      |       |       },                                         | |
      |       |       write,                                     | |
      |       |       set-component-index 1,                     | |
      |       |       process-dependency                         | |
      |       |     }                                            | |
      |       |   }                                              | |
      |       | })                                               | |
      |       +==================================================+ |
      |     ]                                                      |
      |   }                                                        |
      | ])                                                         |
      +============================================================+

    Figure 4: Encrypted Personalization Data
~~~~

For the full SUIT Manifest example binary, see {{suit-personalization}}.


## Success Message

The Success message is used by the TEEP Agent to return a success in
response to an Update message.

Like other TEEP messages, the Success message is
signed, and the relevant CDDL snippet is shown below.
The complete CDDL structure is shown in Appendix C.

~~~~ cddl-teep-success
teep-success = [
  type: TEEP-TYPE-teep-success,
  options: {
    ? token => bstr .size (8..64),
    ? msg => text .size (1..128),
    ? suit-reports => [ + SUIT_Report ],
    * $$teep-success-extensions,
    * $$teep-option-extensions
  }
]
~~~~

The Success message has the following fields:

{: vspace='0'}
type
: The value of (5) corresponds to corresponds to a Success message sent from the TEEP Agent to the
  TAM.

token
: The value in the token parameter is used to match responses to requests.
  It MUST match the value of the token parameter in the Update
  message the Success is in response to, if one was present.  If none was
  present, the token MUST be absent in the Success message.

msg
: The msg parameter contains optional diagnostics information encoded in
  UTF-8 {{RFC3629}} using Net-Unicode form {{RFC5198}} with max 128 bytes
  returned by the TEEP Agent.

suit-reports
: If present, the suit-reports parameter contains a set of SUIT Reports
  as defined in Section 4 of {{I-D.ietf-suit-report}}.
  If a token parameter was present in the Update
  message the Success message is in response to,
  the suit-report-nonce field MUST be present in the SUIT Report with a
  value matching the token parameter in the Update
  message.

## Error Message {#error-message-def}

The Error message is used by the TEEP Agent to return an error in
response to a message from the TAM.

Like other TEEP messages, the Error message is
signed, and the relevant CDDL snippet is shown below.
The complete CDDL structure is shown in Appendix C.

~~~~ cddl-teep-error
teep-error = [
  type: TEEP-TYPE-teep-error,
  options: {
     ? token => bstr .size (8..64),
     ? err-msg => text .size (1..128),
     ? supported-teep-cipher-suites => [ + $teep-cipher-suite ],
     ? supported-freshness-mechanisms => [ + $freshness-mechanism ],
     ? challenge-tam => bstr .size (8..512),
     ? versions => [ + version ],
     ? suit-reports => [ + SUIT_Report ],
     * $$teep-error-extensions,
     * $$teep-option-extensions
  },
  err-code: (0..23)
]

; The err-code parameter, uint (0..23)
ERR_PERMANENT_ERROR = 1
ERR_UNSUPPORTED_EXTENSION = 2
ERR_UNSUPPORTED_FRESHNESS_MECHANISMS = 3
ERR_UNSUPPORTED_MSG_VERSION = 4
ERR_UNSUPPORTED_CIPHER_SUITES = 5
ERR_BAD_CERTIFICATE = 6
ERR_ATTESTATION_REQUIRED = 7
ERR_CERTIFICATE_EXPIRED = 9
ERR_TEMPORARY_ERROR = 10
ERR_MANIFEST_PROCESSING_FAILED = 17
~~~~

The Error message has the following fields:

{: vspace='0'}
type
: The value of (6) corresponds to an Error message sent from the TEEP Agent to the TAM.

token
: The value in the token parameter is used to match responses to requests.
  It MUST match the value of the token parameter in the
  message the Success is in response to, if one was present.  If none was
  present, the token MUST be absent in the Error message.

err-msg
: The err-msg parameter is human-readable diagnostic text that MUST be encoded
  using UTF-8 {{RFC3629}} using Net-Unicode form {{RFC5198}} with max 128 bytes.

supported-teep-cipher-suites
: The supported-teep-cipher-suites parameter lists the TEEP cipher suite(s) supported by the TEEP Agent.
  Details about the cipher suite encoding can be found in {{teep-ciphersuite}}.
  This otherwise optional parameter MUST be returned if err-code is ERR_UNSUPPORTED_CIPHER_SUITES.

supported-freshness-mechanisms
: The supported-freshness-mechanisms parameter lists the freshness mechanism(s) supported by the TEEP Agent.
  Details about the encoding can be found in {{freshness-mechanisms}}.
  This otherwise optional parameter MUST be returned if err-code is ERR_UNSUPPORTED_FRESHNESS_MECHANISMS.

challenge-tam
: The challenge-tam field is an optional parameter used for ensuring the freshness of
  attestation evidence included with a QueryRequest message.
  When a challenge-tam is provided in the Error message and Evidence in the form of an EAT is
  returned with a QueryRequest message then the challenge-tam contained in the Error message
  MUST be used to generate the EAT, by copying the challenge-tam value into the eat_nonce claim, as described in the
  EAT profile {{eat}} if using the Nonce freshness mechanism.
  For more details see {{freshness-mechanisms}}.

  If any format other than EAT is used, it is up to that
  format to define the use of the challenge-tam field.

versions
: The versions parameter enumerates the TEEP protocol version(s) supported by the TEEP
  Agent. This otherwise optional parameter MUST be returned if err-code is ERR_UNSUPPORTED_MSG_VERSION.

suit-reports
: If present, the suit-reports parameter contains a set of SUIT Reports
  as defined in Section 4 of {{I-D.ietf-suit-report}}.  If
  a token parameter was present in the Update message the Error message is in response to,
  the suit-report-nonce field MUST be present in the SUIT Report with a
  value matching the token parameter in the Update
  message.

err-code
: The err-code parameter contains one of the
  error codes listed below). Only selected values are applicable
  to each message.

This specification defines the following initial error messages:

{: vspace='0'}
ERR_PERMANENT_ERROR (1)
: The TEEP
  request contained incorrect fields or fields that are inconsistent with
  other fields.
  For diagnosis purposes it is RECOMMMENDED to identify the failure reason
  in the error message.
  A TAM receiving this error might refuse to communicate further with
  the TEEP Agent for some period of time until it has reason to believe
  it is worth trying again, but it should take care not to give up on
  communication.  In contrast, ERR_TEMPORARY_ERROR is an indication
  that a more aggressive retry is warranted.

ERR_UNSUPPORTED_EXTENSION (2)
: The TEEP Agent does not support an extension included in the request
  message.
  For diagnosis purposes it is RECOMMMENDED to identify the unsupported
  extension in the error message.
  A TAM receiving this error might retry the request without using extensions.

ERR_UNSUPPORTED_FRESHNESS_MECHANISMS (3)
: The TEEP Agent does not
  support any freshness algorithm mechanisms in the request message.
  A TAM receiving this error might retry the request using a different
  set of supported freshness mechanisms in the request message.

ERR_UNSUPPORTED_MSG_VERSION (4)
: The TEEP Agent does not
  support the TEEP protocol version indicated in the request message.
  A TAM receiving this error might retry the request using a different
  TEEP protocol version.

ERR_UNSUPPORTED_CIPHER_SUITES (5)
: The TEEP Agent does not
  support any cipher suites indicated in the request message.
  A TAM receiving this error might retry the request using a different
  set of supported cipher suites in the request message.

ERR_BAD_CERTIFICATE (6)
: Processing of a certificate failed. For diagnosis purposes it is
  RECOMMMENDED to include information about the failing certificate
  in the error message.  For example, the certificate was of an
  unsupported type, or the certificate was revoked by its signer.
  A TAM receiving this error might attempt to use an alternate certificate.

ERR_ATTESTATION_REQUIRED (7)
: Indicates attestation of the TAM is required at the TEEP Agent side, and to request
  additional round of QueryRequest and QueryResponse to be performed before
  proceeding to update message.

ERR_CERTIFICATE_EXPIRED (9)
: A certificate has expired or is not currently
  valid.
  A TAM receiving this error might attempt to renew its certificate
  before using it again.

ERR_TEMPORARY_ERROR (10)
: A miscellaneous
  temporary error, such as a memory allocation failure, occurred while processing the request message.
  A TAM receiving this error might retry the same request at a later point
  in time.

ERR_MANIFEST_PROCESSING_FAILED (17)
: The TEEP Agent encountered one or more manifest processing failures.
  If the suit-reports parameter is present, it contains the failure details.
  A TAM receiving this error might still attempt to install or update
  other components that do not depend on the failed manifest.

New error codes should be added sparingly, not for every implementation
error.  That is the intent of the err-msg field, which can be used to
provide details meaningful to humans.  New error codes should only be
added if the TAM is expected to do something behaviorally different upon
receipt of the error message, rather than just logging the event.
Hence, each error code is responsible for saying what the
behavioral difference is expected to be.

# EAT Profile {#eat}

The TEEP protocol operates between a TEEP Agent and a TAM.  While
the TEEP protocol does not require use of EAT, use of EAT is encouraged and
{{query-response}} explicitly defines a way to carry an Entity Attestation Token
in a QueryResponse.  

As discussed in {{attestation}}, the content of Evidence is opaque to the TEEP
architecture, but the content of Attestation Results is not, where Attestation
Results flow between a Verifier and a TAM (as the Relying Party).
Although Attestation Results required by a TAM are separable from the TEEP protocol
per se, this section is included as part of the requirements for building
a compliant TAM that uses EATs for Attestation Results.

Section 7 of {{I-D.ietf-rats-eat}} defines the requirement for
Entity Attestation Token profiles.  This section defines an EAT profile
for use with TEEP.

* profile-label: The profile-label for this specification is the URI
<https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-12>.
(RFC-editor: upon RFC publication, replace string with
"https://www.rfc-editor.org/info/rfcXXXX" where XXXX is the RFC number
of this document.)

* Use of JSON, CBOR, or both: CBOR only.
* CBOR Map and Array Encoding: Only definite length arrays and maps.
* CBOR String Encoding: Only definite-length strings are allowed.
* CBOR Preferred Serialization: Encoders must use preferred serialization,
  and decoders need not accept non-preferred serialization.
* CBOR Tags: CBOR Tags are not used.
* COSE/JOSE Protection: See {{eat-suit-ciphersuite}}.
* COSE/JOSE Algorithms: See {{eat-suit-ciphersuite}}.
* Detached EAT Bundle Support: DEB use is permitted.
* Key Identification: COSE Key ID (kid) is used, where
  the key ID is the hash of a public key (where the public key may be
  used as a raw public key, or in a certificate).  See {{attestation-result}}
  discussion on the choice of hash algorithm.
* Endorsement Identification: Optional, but semantics are the same
  as in Verification Key Identification.
* Freshness: See {{freshness-mechanisms}} for details.  When the
  eat_nonce claim is used, the value is a single bstr.
* Claims Requirements:
  * The following claims are required: ueid, oemid,
  hwmodel, hwversion, manifests, and cnf.  See {{attestation}} for discussion.  Other claims are optional.
  * See {{freshness-mechanisms}} for discussion affecting whether the
  eat_nonce claim is used.
  * The sw-name claim for a Trusted
  Component holds the URI of the SUIT manifest for that component.
  * The manifests claim uses a SUIT manifest, where the manifest
    body contains a SUIT_Reference as defined in Section 4 of
    {{I-D.ietf-suit-report}}, and the content type is as defined
    in {{I-D.ietf-suit-report}}.

A TAM implementation might simply accept a TEEP Agent as trustworthy based on a
successful Attestation Result, and if not then attempt to update the TEEP Agent
and all of its dependencies.  This logic is simple but it might result in updating
some components that do not need to be updated.

An alternate TAM implementation might use any Additional Claims to determine whether
the TEEP Agent or any of its dependencies are trustworthy, and only update the
specific components that are out of date.

## Relationship to AR4SI

{{I-D.ietf-rats-ar4si}} defines an EAT profile for arbitrary Relying Parties
to use with Attestation Results.  However the TAM as a Relying Party needs specific
claims that are not required in the AR4SI profile, and so needs its own more
specific profile.

In some deployments, a TAM can be used as an intermediary between Verifier and a
TEEP Agent acting as an Attester in the Passport model or acting as a Relying
Party in the Background Check Model of {{RFC9334}}.  This is depicted in the
example in Figure 1.  In such a case, both profiles need to be obtained from the
Verifier: one for use by the TAM itself, and the other to pass on to the TEEP
Agent.

When the TAM and Verifier are combined into the same implementation, obtaining
both profiles can be straightforward, but when they are on different machines,
the situation is more complex, especially if Nonces are used to ensure freshness
of Evidence. There are thus several such cases:

1. The protocol between the TAM and the Verifier (which is outside
   the scope of TEEP itself) allows requesting multiple Attestation Results from
   the same Evidence.  In this case, the TAM can request both EAT profiles be
   returned.
2. The protocol between the TAM and the Verifier only allows requesting one
   Attestation Result format, but the Evidence freshness mechanism does not use
   Nonces.  In this case, the TAM can send the same Evidence in two separate
   requests, each requesting a different EAT profile for the Attestation Results.
3. The protocol between the TAM and the Verifier only allows requesting one
   Attestation Result format, and the Evidence freshness mechanism uses Nonces.
   In this case, it is simpler to not have the TAM be an intermediary, since
   the Verifier will require a separate Nonce for each Attestation Result, but
   have the Attester or Relying Party contact the Verifier directly to get
   Attestation Results in the AR4SI profile.

# Mapping of TEEP Message Parameters to CBOR Labels {#tags}

In COSE, arrays and maps use strings, negative integers, and unsigned
integers as their keys. Integers are used for compactness of
encoding. Since the word "key" is mainly used in its other meaning, as a
cryptographic key, this specification uses the term "label" for this usage
as a map key.

This specification uses the following mapping:

| Name                             | Label |
| supported-teep-cipher-suites     |     1 |
| challenge-agent                  |     2 |
| versions                         |     3 |
| supported-suit-cose-profiles     |     4 |
| selected-teep-cipher-suite       |     5 |
| selected-version                 |     6 |
| attestation-payload              |     7 |
| tc-list                          |     8 |
| ext-list                         |     9 |
| manifest-list                    |    10 |
| msg                              |    11 |
| err-msg                          |    12 |
| attestation-payload-format       |    13 |
| requested-tc-list                |    14 |
| unneeded-manifest-list           |    15 |
| component-id                     |    16 |
| tc-manifest-sequence-number      |    17 |
| have-binary                      |    18 |
| suit-reports                     |    19 |
| token                            |    20 |
| supported-freshness-mechanisms   |    21 |
| challenge-tam                    |    22 |
| err-code                         |    23 |

~~~~ cddl-label
; labels of mapkey for teep message parameters, uint (0..23)
supported-teep-cipher-suites = 1
challenge-agent = 2
versions = 3
supported-suit-cose-profiles = 4
selected-teep-cipher-suite = 5
selected-version = 6
attestation-payload = 7
tc-list = 8
ext-list = 9
manifest-list = 10
msg = 11
err-msg = 12
attestation-payload-format = 13
requested-tc-list = 14
unneeded-manifest-list = 15
component-id = 16
tc-manifest-sequence-number = 17
have-binary = 18
suit-reports = 19
token = 20
supported-freshness-mechanisms = 21
challenge-tam = 2
err-code = 23
~~~~

# Behavior Specification

Behavior is specified in terms of the conceptual APIs defined in
section 6.2.1 of {{I-D.ietf-teep-architecture}}.

## TAM Behavior {#tam}

When the ProcessConnect API is invoked, the TAM sends a QueryRequest message.

When the ProcessTeepMessage API is invoked, the TAM first does validation
as specified in {{validation}}, and drops the message if it is not valid.
It may also do additional implementation specific actions such as logging the results
or attempting to update the TEEP Agent to a version that does not send invalid messages.
Otherwise, it proceeds as follows.

If the message includes a token, it can be used to
match the response to a request previously sent by the TAM.
The TAM MUST expire the token value after receiving the first response
from the device that has a valid signature and ignore any subsequent messages that have the same token
value.  The token value MUST NOT be used for other purposes, such as a TAM to
identify the devices and/or a device to identify TAMs or Trusted Components.

### Handling a QueryResponse Message

If a QueryResponse message is received, the TAM verifies the presence of any parameters
required based on the data-items-requested in the QueryRequest, and also validates that
the nonce in any SUIT Report matches the token sent in the QueryRequest message if a token
was present.  If these requirements are not met, the TAM drops the message.  It may also do
additional implementation specific actions such as logging the results.  If the requirements
are met, processing continues as follows.

If a QueryResponse message is received that contains an attestation-payload, the TAM
checks whether it contains Evidence or an Attestation Result by inspecting the attestation-payload-format
parameter.  The media type defined in {{eat}} indicates an Attestation Result, though future
extensions might also indicate other Attestation Result formats in the future. Any other unrecognized
value indicates Evidence.  If it contains an Attestation Result, processing continues as in
{{attestation-result}}.

If the QueryResponse is instead determined to contain Evidence, the TAM passes
the Evidence (via some mechanism out of scope of this document) to an attestation Verifier
(see {{RFC9334}})
to determine whether the Agent is in a trustworthy state.  Once the TAM receives an Attestation
Result from the Verifier, processing continues as in {{attestation-result}}.

#### Handling an Attestation Result {#attestation-result}

The Attestation Result must first be validated as follows:

1. Verify that the Attestation Result was signed by a Verifier that the TAM trusts.
2. Verify that the Attestation Result contains a "cnf" claim (as defined in Section 3.1 of {{RFC8747}}) where
   the key ID is the hash of the TEEP Agent public key used to verify the signature on the TEEP message,
   and the hash is computed using the Digest Algorithm specified by one of the SUIT profiles
   supported by the TAM (SHA-256 for the ones mandated in this document).

   See Sections 3.4 and 6 of {{RFC8747}} for more discussion.

Based on the results of attestation (if any), any SUIT Reports,
and the lists of installed, requested,
and unneeded Trusted Components reported in the QueryResponse, the TAM
determines, in any implementation specific manner, which Trusted Components
need to be installed, updated, or deleted, if any.  There are in typically three cases:

1. Attestation failed. This indicates that the rest of the information in the QueryResponse
   cannot necessarily be trusted, as the TEEP Agent may not be healthy (or at least up to date).
   In this case, the TAM can attempt to use TEEP to update any Trusted Components (e.g., firmware,
   the TEEP Agent itself, etc.) needed to get the TEEP Agent back into an up-to-date state that
   would allow attestation to succeed.
2. Attestation succeeded (so the QueryResponse information can be accepted as valid), but the set
   of Trusted Components needs to be updated based on TAM policy changes or requests from the TEEP Agent.
3. Attestation succeeded, and no changes are needed.

If any Trusted Components need to be installed, updated, or deleted,
the TAM sends an Update message containing SUIT Manifests with command
sequences to do the relevant installs, updates, or deletes.
It is important to note that the TEEP Agent's
Update Procedure requires resolving and installing any dependencies
indicated in the manifest, which may take some time, and the resulting Success
or Error message is generated only after completing the Update Procedure.
Hence, depending on the freshness mechanism in use, the TAM may need to
store data (e.g., a nonce) for some time.  For example, if a mobile device
needs an unmetered connection to download a dependency, it may take
hours or longer before the device has sufficient access.  A different
freshness mechanism, such as timestamps, might be more appropriate in such
cases.

If no Trusted Components need to be installed, updated, or deleted, but the QueryRequest included
Evidence, the TAM MAY (e.g., based on attestation-payload-format parameters received from the TEEP Agent
in the QueryResponse) still send an Update message with no SUIT Manifests, to pass the Attestation
Result back to the TEEP Agent.

### Handling a Success or Error Message

If a Success or Error message is received containing one or more SUIT Reports, the TAM also validates that
the nonce in any SUIT Report matches the token sent in the Update message,
and drops the message if it does not match.  Otherwise, the TAM handles
the update in any implementation specific way, such as updating any locally
cached information about the state of the TEEP Agent, or logging the results.

If the TAM received an Error message with ERR_ATTESTATION_REQUIRED, it indicates that the TEEP Agent is requesting attestation of the TAM.
In this case, the TAM MUST return another QueryRequest containing attestation-payload and/or suit-report to the TEEP Agent before advancing to an Update message.

If any other Error message is received, the TAM can handle it in any implementation
specific way, but {{error-message-def}} provides recommendations for such handling.

## TEEP Agent Behavior {#agent}

When the RequestTA API is invoked, the TEEP Agent first checks whether the
requested TA is already installed.  If it is already installed, the
TEEP Agent passes no data back to the caller.  Otherwise,
if the TEEP Agent chooses to initiate the process of requesting the indicated
TA, it determines (in any implementation specific way) the TAM URI based on
any TAM URI provided by the RequestTA caller and any local configuration,
and passes back the TAM URI to connect to.  It MAY also pass back a
QueryResponse message if all of the following conditions are true:

* The last QueryRequest message received from that TAM contained no token or challenge,
* The ProcessError API was not invoked for that TAM since the last QueryResponse
  message was received from it, and
* The public key or certificate of the TAM is cached and not expired.

When the RequestPolicyCheck API is invoked, the TEEP Agent decides
whether to initiate communication with any trusted TAMs (e.g., it might
choose to do so for a given TAM unless it detects that it has already
communicated with that TAM recently). If so, it passes back a TAM URI
to connect to.  If the TEEP Agent has multiple TAMs it needs to connect
with, it just passes back one, with the expectation that
RequestPolicyCheck API will be invoked to retrieve each one successively
until there are no more and it can pass back no data at that time.
Thus, once a TAM URI is returned, the TEEP Agent can remember that it has
already initiated communication with that TAM.

When the ProcessError API is invoked, the TEEP Agent can handle it in
any implementation specific way, such as logging the error or
using the information in future choices of TAM URI.

When the ProcessTeepMessage API is invoked, the Agent first does validation
as specified in {{validation}}, and if it is not valid then the Agent
responds with an Error message.
Otherwise, processing continues as follows based on the type of message.

When a QueryRequest message is received, the Agent responds with a
QueryResponse message if all fields were understood, or an Error message
if any error was encountered.

If the TEEP Agent requires attesting the TAM, the TEEP Agent MUST send Error Message with ERR_ATTESTATION_REQUIRED supplying supported-freshness-mechanisms or challenge-tam.

When an Update message is received, the Agent attempts to unlink any
SUIT manifests listed in the unneeded-manifest-list field of the message,
and responds with an Error message if any error was encountered.
If the unneeded-manifest-list was empty, or no error was encountered processing it,
the Agent attempts to update
the Trusted Components specified in the SUIT manifests
by following the Update Procedure specified
in {{I-D.ietf-suit-manifest}}, and responds with a Success message if
all SUIT manifests were successfully installed, or an Error message
if any error was encountered.
It is important to note that the
Update Procedure requires resolving and installing any dependencies
indicated in the manifest, which may take some time, and the Success
or Error message is generated only after completing the Update Procedure.

# Cipher Suites {#ciphersuite}


TEEP requires algorithms for various purposes:

* Algorithms for signing TEEP messages exchanged between the TEEP Agent and the TAM.
* Algorithms for signing EAT-based Evidence sent by the Attester via the TEEP Agent and the TAM to the Verifier. (If evidence is not encrypted by the TEEP Agent then it will be opaque to the TEEP Agent and to the TAM.)
* Algorithms for encrypting EAT-based Evidence sent by the TEEP Agent to the TAM. (The TAM will decrypt the encrypted Evidence and will forward it to the Verifier.)
* Algorithms for signing and optionally encrypting SUIT reports sent by the TEEP Agent to the TAM.
* Algorithms for signing and optionally encrypting SUIT manifests sent by the Trusted Component Signer to the TEEP Agent.

Further details are provided for the protection of TEEP messages, SUIT Reports, and EATs.


## TEEP Messages {#teep-ciphersuite}

The TEEP protocol uses COSE for protection of TEEP messages in both directions.
To negotiate cryptographic mechanisms and algorithms, the TEEP protocol defines the following cipher suite structure,
which is used to specify an ordered set of operations (e.g., sign) done as part of composing a TEEP message.
Although this specification only specifies the use of signing and relies on payload encryption to protect sensitive
information, future extensions might specify support for encryption and/or MAC operations if needed.

~~~~ cddl-cipher-suite
; teep-cipher-suites
$teep-cipher-suite /= teep-cipher-suite-sign1-eddsa
$teep-cipher-suite /= teep-cipher-suite-sign1-es256

;The following two cipher suites have only a single operation each.
;Other cipher suites may be defined to have multiple operations.
;MANDATORY for TAM to support them, and OPTIONAL
;to support any additional ones that use COSE_Sign_Tagged, or other
;signing, encryption, or MAC algorithms.

teep-operation-sign1-eddsa = [ cose-sign1, cose-alg-eddsa ]
teep-operation-sign1-es256 = [ cose-sign1, cose-alg-es256 ]

teep-cipher-suite-sign1-eddsa = [ teep-operation-sign1-eddsa ]
teep-cipher-suite-sign1-es256 = [ teep-operation-sign1-es256 ]

;MANDATORY for TAM and TEEP Agent to support the following COSE
;operations, and OPTIONAL to support additional ones such as
;COSE_Sign_Tagged, COSE_Encrypt0_Tagged, etc.

cose-sign1 = 18      ; CoAP Content-Format value

;MANDATORY for TAM to support the following, and OPTIONAL to implement
;any additional algorithms from the IANA COSE Algorithms registry.

cose-alg-es256 = -7  ; ECDSA w/ SHA-256
cose-alg-eddsa = -8  ; EdDSA
~~~~

Each operation in a given cipher suite has two elements:

* a COSE-type defined in Section 2 of {{RFC9052}} that identifies the type of operation, and
* a specific cryptographic algorithm as defined in the COSE Algorithms registry {{COSE.Algorithm}} to be used to perform that operation.

A TAM MUST support both of the cipher suites defined above.  A TEEP Agent MUST support at least
one of the two but can choose which one.  For example, a TEEP Agent might
choose a given cipher suite if it has hardware support for it.
A TAM or TEEP Agent MAY also support any other algorithms in the COSE Algorithms
registry in addition to the mandatory ones listed above.  It MAY also support use
with COSE_Sign or other COSE types in additional cipher suites.

Any cipher suites without confidentiality protection can only be added if the
associated specification includes a discussion of security considerations and
applicability, since manifests may carry sensitive information. For example,
Section 6 of {{I-D.ietf-teep-architecture}} permits implementations that
terminate transport security inside the TEE and if the transport security
provides confidentiality then additional encryption might not be needed in
the manifest for some use cases. For most use cases, however, manifest
confidentiality will be needed to protect sensitive fields from the TAM as
discussed in Section 9.8 of {{I-D.ietf-teep-architecture}}.

The cipher suites defined above do not do encryption at the TEEP layer, but
permit encryption of the SUIT payload using a mechanism such as {{I-D.ietf-suit-firmware-encryption}}.
See {{security}} and {{eat-suit-ciphersuite}} for more discussion of specific payloads.

For the initial QueryRequest message, unless the TAM has more specific knowledge about the TEEP Agent
(e.g., if the QueryRequest is sent in response to some underlying transport message that contains a hint),
the message does not use COSE_Sign1 with one of the above cipher suites, but instead uses COSE_Sign with multiple signatures,
one for each algorithm used in any of the cipher suites listed in the supported-teep-cipher-suites
parameter of the QueryRequest, so that a TEEP Agent supporting any one of them can verify a signature.
If the TAM does have specific knowledge about which cipher suite the TEEP Agent supports,
it MAY instead use that cipher suite with the QueryRequest.

For an Error message with code ERR_UNSUPPORTED_CIPHER_SUITES, the TEEP Agent MUST
protect it with any of the cipher suites mandatory for the TAM.

For all other TEEP messages between the TAM and TEEP Agent,
the selected TEEP cipher suite MUST be used in both directions.

## EATs and SUIT Reports {#eat-suit-ciphersuite}

TEEP uses COSE for confidentiality of EATs and SUIT Reports sent by a TEEP Agent.
The TEEP Agent obtains a signed EAT and then SHOULD encrypt it using the TAM
as the recipient. A SUIT Report is created by a SUIT processor, which
is part of the TEEP Agent itself. The TEEP Agent is therefore in control of signing
the SUIT Report and SHOULD encrypt it. Again, the TAM is the recipient of the encrypted
content. For content-key distribution Ephemeral-Static Diffie-Hellman is used
in this specification. See Section 8.5.5 and Appendix B of {{RFC9052}} for more details.
(If {{I-D.ietf-suit-firmware-encryption}} is used, it is also the same as discussed in
Section 6.2 of that document.)

To perform encryption with ECDH the TEEP Agent needs to be in possession of the public
key of the recipient, i.e., the TAM. See Section 5 of {{I-D.ietf-teep-architecture}}
for more discussion of TAM keys used by the TEEP Agent.

This specification defines cipher suites for confidentiality protection of EATs and
SUIT Reports. The TAM MUST support each cipher suite defined below, based on definitions in
{{I-D.ietf-suit-mti}}.  A TEEP Agent MUST support at least one of the cipher
suites below but can choose which one.  For example, a TEEP Agent might
choose a given cipher suite if it has hardware support for it.
A TAM or TEEP Agent MAY also support other algorithms in the COSE Algorithms registry.
It MAY also support use with COSE_Encrypt or other COSE types in additional cipher suites.

~~~~ cddl-suit-cose-profile
; suit-cose-profile
$suit-cose-profile /= suit-sha256-es256-ecdh-a128gcm
$suit-cose-profile /= suit-sha256-eddsa-ecdh-a128gcm
~~~~

# Freshness Mechanisms {#freshness-mechanisms}

A freshness mechanism determines how a TAM can tell whether an attestation payload provided
in a QueryResponse is fresh.  There are multiple ways this can be done
as discussed in Section 10 of {{RFC9334}}.

Each freshness mechanism is identified with an integer value, which corresponds to
an IANA registered freshness mechanism (see the IANA Considerations section of
{{I-D.ietf-rats-reference-interaction-models}}).
This document uses the following freshness mechanisms which may be added to in the
future by TEEP extensions:

~~~~ cddl-freshness
; freshness-mechanisms
FRESHNESS_NONCE = 0
FRESHNESS_TIMESTAMP = 1

$freshness-mechanism /= FRESHNESS_NONCE
$freshness-mechanism /= FRESHNESS_TIMESTAMP
~~~~

An implementation MUST support the Nonce mechanism and MAY support additional
mechanisms.

In the Nonce mechanism, the attestation payload MUST include a nonce provided
in the QueryRequest challenge if the Background Check model is used, or in
the QueryRequest token if the Passport model is used.  The timestamp mechanism uses a timestamp
determined via mechanisms outside the TEEP protocol,
and the challenge is only needed in the QueryRequest message
if a challenge is needed in generating the attestation payload for reasons other
than freshness.

If a TAM supports multiple freshness mechanisms that require different challenge
formats, the QueryRequest message can currently only send one such challenge.
This situation is expected to be rare, but should it occur, the TAM can
choose to prioritize one of them and exclude the other from the
supported-freshness-mechanisms in the QueryRequest, and resend the QueryRequest
with the other mechanism if an ERR_UNSUPPORTED_FRESHNESS_MECHANISMS Error
is received that indicates the TEEP Agent supports the other mechanism.

# Security Considerations {#security}

This section summarizes the security considerations discussed in this
specification:

{: vspace='0'}
Cryptographic Algorithms
: TEEP protocol messages exchanged between the TAM and the TEEP Agent
  are protected using COSE. This specification relies on the
  cryptographic algorithms provided by COSE.  Public key based
  authentication is used by the TEEP Agent to authenticate the TAM
  and vice versa.

Attestation
: A TAM relies on signed Attestation Results provided by a Verifier,
  either obtained directly using a mechanism outside the TEEP protocol
  (by using some mechanism to pass Evidence obtained in the attestation payload of
  a QueryResponse, and getting back the Attestation Results), or indirectly
  via the TEEP Agent forwarding the Attestation Results in the attestation
  payload of a QueryResponse. See the security considerations of the
  specific mechanism in use (e.g., EAT) for more discussion.

  An impersonation attack, where one TEEP Agent attempts to use the attestation
  payload of another TEEP Agent, can be prevented using a proof-of-possession
  approach.  The "cnf" claim is mandatory in the EAT profile for EAT for this
  purpose.  See Section 6 of {{RFC8747}} and {{attestation-result}} of this document
  for more discussion.

Trusted Component Binaries
: Each Trusted Component binary is signed by a Trusted Component Signer. It is the responsibility of the
  TAM to relay only verified Trusted Components from authorized Trusted Component Signers.  Delivery of
  a Trusted Component to the TEEP Agent is then the responsibility of the TAM,
  using the security mechanisms provided by the TEEP
  protocol.  To protect the Trusted Component binary, the SUIT manifest format is used and
  it offers a variety of security features, including digital
  signatures and content encryption, if a SUIT mechanism such as {{I-D.ietf-suit-firmware-encryption}}
  is used.

Personalization Data
: A Trusted Component Signer or TAM can supply personalization data along with a Trusted Component.
  This data is also protected by a SUIT manifest. Personalization data is signed and encrypted
  by a Trusted Component Signer, if a SUIT mechanism such as {{I-D.ietf-suit-firmware-encryption}}
  is used.

TEEP Broker
: As discussed in section 6 of {{I-D.ietf-teep-architecture}},
  the TEEP protocol typically relies on a TEEP Broker to relay messages
  between the TAM and the TEEP Agent.  When the TEEP Broker is
  compromised it can drop messages, delay the delivery of messages,
  and replay messages but it cannot modify those messages. (A replay
  would be, however, detected by the TEEP Agent.) A compromised TEEP
  Broker could reorder messages in an attempt to install an old
  version of a Trusted Component. Information in the manifest ensures that TEEP
  Agents are protected against such downgrade attacks based on
  features offered by the manifest itself.

Trusted Component Signer Compromise
: A TAM is responsible for vetting a Trusted Component and
  before distributing them to TEEP Agents.  
  It is RECOMMENDED to provide a way to
  update the trust anchor store used by the TEE, for example using
  a firmware update mechanism such as {{I-D.ietf-rats-concise-ta-stores}}.  Thus, if a Trusted Component
  Signer is later compromised, the TAM can update the trust anchor
  store used by the TEE, for example using a firmware update mechanism.

CA Compromise
: The CA issuing certificates to a TEE or a Trusted Component Signer might get compromised.
  It is RECOMMENDED to provide a way to update the trust anchor store used by the TEE, for example
  by using a firmware update mechanism, Concise TA Stores {{I-D.ietf-rats-concise-ta-stores}}, Trust
  Anchor Management Protocol (TAMP) {{RFC5934}} or a similar mechanism. If the CA issuing 
  certificates to devices gets compromised then these devices will be rejected by a
  TAM, if revocation is available to the TAM.

TAM Certificate Expiry
: The integrity and the accuracy of the
  clock within the TEE determines the ability to determine an expired
  TAM certificate, if certificates are used.

Compromised Time Source
: As discussed above, certificate validity checks rely on comparing
  validity dates to the current time, which relies on having a trusted
  source of time, such as {{RFC8915}}.  A compromised time source could
  thus be used to subvert such validity checks.

# Privacy Considerations {#privacy}

Depending on
the properties of the attestation mechanism, it is possible to
uniquely identify a device based on information in the
attestation payload or in the certificate used to sign the
attestation payload.  This uniqueness may raise privacy concerns. To lower the
privacy implications the TEEP Agent MUST present its
attestation payload only to an authenticated and authorized TAM and when using
an EAT, it SHOULD use encryption as discussed in {{I-D.ietf-rats-eat}}, since
confidentiality is not provided by the TEEP protocol itself and
the transport protocol under the TEEP protocol might be implemented
outside of any TEE. If any mechanism other than EAT is used, it is
up to that mechanism to specify how privacy is provided.

Since SUIT Reports can also contain sensitive information, a TEEP Agent
SHOULD also encrypt SUIT Reports as discussed in {{eat-suit-ciphersuite}}.

In addition, in the usage scenario discussed in {{directtam}}, a device
reveals its IP address to the Trusted Component Binary server.  This
can reveal to that server at least a clue as to its location, which
might be sensitive information in some cases.

# IANA Considerations {#IANA}

## Media Type Registration

IANA is requested to assign a media type for
application/teep+cbor.

Type name:
: application

Subtype name:
: teep+cbor

Required parameters:
: none

Optional parameters:
: none

Encoding considerations:
: Same as encoding considerations of
  application/cbor.

Security considerations:
: See Security Considerations Section of this document.

Interoperability considerations:
: Same as interoperability
  considerations of application/cbor as specified in {{RFC8949}}.

Published specification:
: This document.

Applications that use this media type:
: TEEP protocol implementations

Fragment identifier considerations:
: N/A

Additional information:
: Deprecated alias names for this type:
  : N/A

  Magic number(s):
  : N/A

  File extension(s):
  : N/A

  Macintosh file type code(s):
  : N/A

Person to contact for further information:
: teep@ietf.org

Intended usage:
: COMMON

Restrictions on usage:
: none

Author:
: See the "Authors' Addresses" section of this document

Change controller:
: IETF

--- back


# A. Contributors
{: numbered='no'}

We would like to thank Brian Witten (Symantec), Tyler Kim (Solacia), Nick Cook (Arm), and  Minho Yoo (IoTrust) for their contributions
to the Open Trust Protocol (OTrP), which influenced the design of this specification.

# B. Acknowledgements
{: numbered='no'}

We would like to thank Eve Schooler for the suggestion of the protocol name.

We would like to thank Kohei Isobe (TRASIO/SECOM), Ken Takayama (SECOM)
Kuniyasu Suzaki (TRASIO/AIST), Tsukasa Oi (TRASIO), and Yuichi Takita (SECOM)
for their valuable implementation feedback.

We would also like to thank Carsten Bormann and Henk Birkholz for their help with the CDDL.

# C. Complete CDDL
{: numbered='no'}

Valid TEEP messages adhere to the following CDDL data definitions,
except that `SUIT_Envelope` and `SUIT_Component_Identifier` are
specified in {{I-D.ietf-suit-manifest}}.

This section is informative and merely summarizes the normative CDDL
snippets in the body of this document.

~~~~ CDDL
{::include draft-ietf-teep-protocol.cddl}
~~~~

# D. Examples of Diagnostic Notation and Binary Representation
{: numbered='no'}

This section includes some examples with the following assumptions:

- The device will have two TCs with the following SUIT Component Identifiers:
  - \[ 0x000102030405060708090a0b0c0d0e0f \]
  - \[ 0x100102030405060708090a0b0c0d0e0f \]
- SUIT manifest-list is set empty only for example purposes (see Appendix E
  for actual manifest examples)

## D.1. QueryRequest Message
{: numbered='no'}

### D.1.1. CBOR Diagnostic Notation
{: numbered='no'}

~~~~
{::include cbor/query_request.diag.txt}
~~~~

### D.1.2. CBOR Binary Representation
{: numbered='no'}

~~~~

{::include cbor/query_request.hex.txt}
~~~~

## D.2. Entity Attestation Token
{: numbered='no'}

This is shown below in CBOR diagnostic form.  Only the payload signed by
COSE is shown.

### D.2.1. CBOR Diagnostic Notation
{: numbered='no'}

~~~~
/ eat-claim-set = /
{
    / cnf /          8: {
                         / kid / 3 : h'ba7816bf8f01cfea414140de5dae2223'
                                     h'b00361a396177a9cb410ff61f20015ad'
                        },
    / eat_nonce /   10: h'948f8860d13a463e8e',
    / ueid /       256: h'0198f50a4ff6c05861c8860d13a638ea',
    / oemid /      258: h'894823', / IEEE OUI format OEM ID /
    / hwmodel /    259: h'549dcecc8b987c737b44e40f7c635ce8'
                          / Hash of chip model name /,
    / hwversion /  260: ["1.3.4", 1], / Multipartnumeric  /
    / manifests /  273: [
                          [ 60, / application/cbor, TO BE REPLACED /
                                / with the format value for a /
                                / SUIT_Reference once one is allocated /
                            {   / SUIT_Reference /
                              / suit-report-manifest-uri / 1: "https://example.com/manifest.cbor",
                              / suit-report-manifest-digest / 0:[
                                / algorithm-id / -16 / "sha256" /,
                                / digest-bytes / h'a7fd6593eac32eb4be578278e6540c5c'
                                                 h'09cfd7d4d234973054833b2b93030609'
                                ]
                            }
                          ]
                        ]
}
~~~~

## D.3. QueryResponse Message
{: numbered='no'}

### D.3.1. CBOR Diagnostic Notation
{: numbered='no'}

~~~~
{::include cbor/query_response.diag.txt}
~~~~

### D.3.2. CBOR Binary Representation
{: numbered='no'}

~~~~
{::include cbor/query_response.hex.txt}
~~~~

## D.4. Update Message
{: numbered='no'}

### D.4.1. CBOR Diagnostic Notation
{: numbered='no'}

~~~~
{::include cbor/update.diag.txt}
~~~~

### D.4.2. CBOR Binary Representation
{: numbered='no'}

~~~~
{::include cbor/update.hex.txt}
~~~~

## D.5. Success Message
{: numbered='no'}

### D.5.1. CBOR Diagnostic Notation
{: numbered='no'}

~~~~
{::include cbor/teep_success.diag.txt}
~~~~

### D.5.2. CBOR Binary Representation
{: numbered='no'}

~~~~
{::include cbor/teep_success.hex.txt}
~~~~

## D.6. Error Message
{: numbered='no'}

### D.6.1. CBOR Diagnostic Notation
{: numbered='no'}

~~~~
{::include cbor/teep_error.diag.txt}
~~~~

### D.6.2. CBOR binary Representation
{: numbered='no'}

~~~~
{::include cbor/teep_error.hex.txt}
~~~~

# E. Examples of SUIT Manifests {#suit-examples}
{: numbered='no'}

This section shows some examples of SUIT manifests described in {{update-msg-def}}.

The examples are signed using the following ECDSA secp256r1 key with SHA256 as the digest function.

COSE_Sign1 Cryptographic Key:

~~~~
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgApZYjZCUGLM50VBC
CjYStX+09jGmnyJPrpDLTz/hiXOhRANCAASEloEarguqq9JhVxie7NomvqqL8Rtv
P+bitWWchdvArTsfKktsCYExwKNtrNHXi9OB3N+wnAUtszmR23M4tKiW
-----END PRIVATE KEY-----
~~~~

The corresponding public key can be used to verify these examples:

~~~~
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhJaBGq4LqqvSYVcYnuzaJr6qi/Eb
bz/m4rVlnIXbwK07HypLbAmBMcCjbazR14vTgdzfsJwFLbM5kdtzOLSolg==
-----END PUBLIC KEY-----
~~~~


## Example 1: SUIT Manifest pointing to URI of the Trusted Component Binary {#suit-uri}
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
{::include cbor/suit_uri.diag.txt}
~~~~

### CBOR Binary in Hex
{: numbered='no'}

~~~~
{::include cbor/suit_uri.hex.txt}
~~~~


## Example 2: SUIT Manifest including the Trusted Component Binary {#suit-integrated}
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
{::include cbor/suit_integrated.diag.txt}
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
{::include cbor/suit_integrated.hex.txt}
~~~~


## Example 3: Supplying Personalization Data for Trusted Component Binary {#suit-personalization}
{: numbered='no'}

### CBOR Diagnostic Notation of SUIT Manifest
{: numbered='no'}

~~~~
{::include cbor/suit_personalization.diag.txt}
~~~~


### CBOR Binary in Hex
{: numbered='no'}

~~~~
{::include cbor/suit_personalization.hex.txt}
~~~~

The Personalization Data above is encrypted with A128KW.
The secret key is h'61616161616161616161616161616161' (0x61 = 'a', and the length is 16).

# F. Examples of SUIT Reports {#suit-reports}
{: numbered='no'}

This section shows some examples of SUIT reports.

## F.1. Example 1: Success
{: numbered='no'}

SUIT Reports have no records if no conditions have failed.
The URI in this example is the reference URI provided in the SUIT manifest.

~~~~
{
  / suit-report-manifest-digest / 1:<<[
    / algorithm-id / -16 / "sha256" /,
    / digest-bytes / h'a7fd6593eac32eb4be578278e6540c5c'
                     h'09cfd7d4d234973054833b2b93030609'
  ]>>,
  / suit-report-manifest-uri / 2: "tam.teep.example/personalisation.suit",
  / suit-report-records / 4: []
}
~~~~

## F.2. Example 2: Faiure
{: numbered='no'}

~~~~
{
  / suit-report-manifest-digest / 1:<<[
    / algorithm-id / -16 / "sha256" /,
    / digest-bytes / h'a7fd6593eac32eb4be578278e6540c5c09cfd7d4d234973054833b2b93030609'
  ]>>,
  / suit-report-manifest-uri / 2: "tam.teep.example/personalisation.suit",
  / suit-report-records / 4: [
    {
      / suit-record-manifest-id / 1:[],
      / suit-record-manifest-section / 2: 7 / dependency-resolution /,
      / suit-record-section-offset / 3: 66,
      / suit-record-dependency-index / 5: 0,
      / suit-record-failure-reason / 6: 404
    }
  ]
}
~~~~

where the dependency-resolution refers to:

~~~~
{
  authentication-wrapper,
  / manifest / 3:<<{
    / manifest-version / 1:1,
    / manifest-sequence-number / 2:3,
    common,
    dependency-resolution,
    install,
    validate,
    run,
    text
  }>>,
}
~~~~

and the suit-record-section-offset refers to:

~~~~
<<[
  / directive-set-dependency-index / 13,0 ,
  / directive-set-parameters / 19,{
    / uri / 21:'tam.teep.example/'
               'edd94cd8-9d9c-4cc8-9216-b3ad5a2d5b8a.suit',
    } ,
  / directive-fetch / 21,2 ,
  / condition-image-match / 3,15
]>>,
~~~~
