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
date: 2020
author:

 -
  ins: H. Tschofenig
  name: Hannes Tschofenig
  org: Arm Ltd.
  street: ''
  city: Absam
  region: Tirol
  code: '6067'
  country: Austria
  email: hannes.tschofenig@arm.com

 -
  ins: M. Pei
  name: Mingliang Pei
  org: Broadcom
  street: 350 Ellis St
  city: Mountain View
  region: CA
  code: '94043'
  country: USA
  email: mingliang.pei@broadcom.com

 -
  ins: D. Wheeler
  name: David Wheeler
  org: Intel
  street: ''
  city: ''
  region: ''
  code: ''
  country: US
  email: david.m.wheeler@intel.com

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
  org: AIST
  street: ''
  city: ''
  region: ''
  code: ''
  country: JP
  email: akira.tsukamoto@aist.go.jp

normative:
  RFC8152: 
  RFC3629: 
  RFC5198: 
  RFC7049: 
  I-D.ietf-rats-eat: 
  I-D.ietf-suit-manifest: 
  I-D.moran-suit-report: 
  RFC2560: 
informative:
  I-D.ietf-teep-architecture: 
  RFC8610: 
  RFC8126: 
  RFC8915: 

--- abstract


This document specifies a protocol that installs, updates, and deletes
Trusted Applications (TAs) in a device with a Trusted Execution
Environment (TEE).  This specification defines an interoperable
protocol for managing the lifecycle of TAs.

The protocol name is pronounced teepee. This conjures an image of a
wedge-shaped protective covering for one's belongings, which sort of
matches the intent of this protocol.

--- middle

# Introduction {#introduction}

The Trusted Execution Environment (TEE) concept has been designed to
separate a regular operating system, also referred as a Rich Execution
Environment (REE), from security-sensitive applications. In a TEE
ecosystem, device vendors may use different operating systems in the
REE and may use different types of TEEs. When TA Developers or
Device Administrators use Trusted Application Managers (TAMs) to
install, update, and delete Trusted Applications (TAs) on a wide range
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
each TA, any dependencies the TA has, and personalization data as separate
components that are expressed in SUIT manifests, and a SUIT manifest
might contain or reference multiple binaries (see {{I-D.ietf-suit-manifest}}
for more details).

As such, the term Trusted Component in this document refers to a
set of binaries expressed in a SUIT manifest, to be installed in
a TEE.  Note that a Trusted Component may include one or more TAs
and/or configuration data and keys needed by a TA to operate correctly.

Each Trusted Component is uniquely identified by a SUIT Component Identifier
(see {{I-D.ietf-suit-manifest}} Section 8.7.2.2).

# Message Overview {#messages}

The TEEP protocol consists of messages exchanged between a TAM
and a TEEP Agent.
The messages are encoded in CBOR and designed to provide end-to-end security.
TEEP protocol messages are signed by the endpoints, i.e., the TAM and the
TEEP Agent, but Trusted
Applications may also be encrypted and signed by a TA Developer or
Device Administrator.
The TEEP protocol not only uses
CBOR but also the respective security wrapper, namely COSE {{RFC8152}}. Furthermore, for software updates the SUIT
manifest format {{I-D.ietf-suit-manifest}} is used, and
for attestation the Entity Attestation Token (EAT) {{I-D.ietf-rats-eat}}
format is supported although other attestation formats are also permitted.

This specification defines six messages.

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


With the Install message a TAM can instruct a TEEP Agent to install
a Trusted Component.
The TEEP Agent will process the message, determine whether the TAM is authorized
and whether the
Trusted Component has been signed by an authorized TA Signer.
If the Install message was processed successfully
then a
Success message is returned to the TAM, or an Error message otherwise.

~~~~
 +------------+           +-------------+
 | TAM        |           |TEEP Agent   |
 +------------+           +-------------+

             Install ---->

                            Success

                    <----    or

                            Error
~~~~


With the Delete message a TAM can instruct a TEEP Agent to delete
one or multiple Trusted Components.
A Success message is returned when the operation has been completed successfully,
or an Error message
otherwise.

~~~~
 +------------+           +-------------+
 | TAM        |           |TEEP Agent   |
 +------------+           +-------------+

             Delete  ---->

                            Success

                    <----    or

                            Error
~~~~



# Detailed Messages Specification {#detailmsg}

TEEP messages are protected by the COSE_Sign1 structure.
The TEEP protocol messages are described in CDDL format {{RFC8610}} below.

~~~~
{
    teep-message                => (query-request /
                                    query-response /
                                    install /
                                    delete /
                                    teep-success /
                                    teep-error ),
}
~~~~


## Creating and Validating TEEP Messages

### Creating a TEEP message

To create a TEEP message, the following steps are performed.

1. Create a TEEP message according to the description below and populate
  it with the respective content.

1. Create a COSE Header containing the desired set of Header
  Parameters.  The COSE Header MUST be valid per the {{RFC8152}} specification.

1. Create a COSE_Sign1 object
  using the TEEP message as the COSE_Sign1 Payload; all
  steps specified in {{RFC8152}} for creating a
  COSE_Sign1 object MUST be followed.

1. Prepend the COSE object with the
  TEEP CBOR tag to indicate that the CBOR-encoded message is indeed a
  TEEP message.



### Validating a TEEP Message

When validating a TEEP message, the following steps are performed. If any
of
the listed steps fail, then the TEEP message MUST be rejected.



1. Verify that the received message is a valid CBOR object.

1. Remove the TEEP message CBOR tag and verify
  that one of the COSE CBOR tags follows it.

1. Verify that the message contains a COSE_Sign1 structure.

1. Verify that the resulting COSE Header includes only parameters
  and values whose syntax and semantics are both understood and
  supported or that are specified as being ignored when not
  understood.

1. Follow the steps specified in Section 4 of {{RFC8152}} ("Signing Objects") for
  validating a COSE_Sign1 object. The COSE_Sign1 payload is the content
  of the TEEP message.

1. Verify that the TEEP message is a valid CBOR map and verify the fields of
  the
  TEEP message according to this specification.




## QueryRequest Message


A QueryRequest message is used by the TAM to learn 
information from the TEEP Agent, such as
the features supported by the TEEP Agent, including 
ciphersuites, and protocol versions. Additionally, 
the TAM can selectively request data items from the 
TEEP Agent via the request parameter. Currently, 
the following features are supported: 

 - Request for attestation information,
 - Listing supported extensions, 
 - Querying installed Trusted Components, and 
 - Listing supporting SUIT commands.

Like other TEEP messages, the QueryRequest message is
signed, and the relevant CDDL snippet is shown below. 
The complete CDDL structure is shown in {{CDDL}}.

~~~~
query-request = [
  type: TEEP-TYPE-query-request,
  options: {
    ? token => uint,
    ? supported-cipher-suites => [ + suite ],
    ? challenge => bstr .size (8..64),
    ? versions => [ + version ],
    ? ocsp-data => bstr,
    * $$query-request-extensions
    * $$teep-option-extensions
  },
  data-item-requested: data-item-requested  
]
~~~~

The message has the following fields: 

{: vspace='0'}
type
: The value of (1) corresponds to a QueryRequest message sent from the TAM to 
  the TEEP Agent.

token
: The value in the token parameter is used to match responses to requests. This is 
particularly useful when a TAM issues multiple concurrent requests to a TEEP Agent. The token is not needed when the attestation bit is set in the data-item-requested value.

data-item-requested
: The data-item-requested parameter indicates what information the TAM requests from the TEEP
  Agent in the form of a bitmap. Each value in the bitmap corresponds to an 
  IANA registered information element. This 
  specification defines the following initial set of information elements:

   attestation (1)
   : With this value the TAM requests the TEEP Agent to return attestation
     evidence (e.g., an EAT) in the response.

   trusted-components (2)
   : With this value the TAM queries the TEEP Agent for all installed Trusted Components.

   extensions (4)
   : With this value the TAM queries the TEEP Agent for supported capabilities
     and extensions, which allows a TAM to discover the capabilities of a TEEP
     Agent implementation.

   suit-commands (8)
   : With this value the TAM queries the TEEP Agent for supported commands offered
     by the SUIT manifest implementation.
  
   Further values may be added in the future via IANA registration.

supported-cipher-suites
: The supported-cipher-suites parameter lists the ciphersuite(s) supported by the TAM. If this parameter is not present, it is to be treated the same as if
  it contained both ciphersuites defined in this document. Details
  about the ciphersuite encoding can be found in {{ciphersuite}}.

challenge
: The challenge field is an optional parameter used for ensuring the refreshness of the
  attestation evidence returned with a QueryResponse message. When a challenge is 
  provided in the QueryRequest and an EAT is returned with the QueryResponse message
  then the challenge contained in this request MUST be copied into the nonce claim found 
  in the EAT. If any format other than EAT is used, it is up to that
  format to define the use of the challenge field.

versions
: The versions parameter enumerates the TEEP protocol version(s) supported by the TAM
  A value of 0 refers to the current version of the TEEP protocol.
  If this field is not present, it is to be treated the same as if
  it contained only version 0.

ocsp-data
: The ocsp-data parameter contains a list of OCSP stapling data
  respectively for the TAM certificate and each of the CA certificates
  up to the root certificate. The TAM provides OCSP data so that the
  TEEP Agent can validate the status of the TAM certificate chain
  without making its own external OCSP service call. OCSP data MUST be
  conveyed as a DER-encoded OCSP response (using the ASN.1 type
  OCSPResponse defined in {{RFC2560}}). The use of OCSP is OPTIONAL to
  implement for both the TAM and the TEEP Agent. A TAM can query the
  TEEP Agent for the support of this functionality via the capability
  discovery exchange, as described above.


## QueryResponse Message

The QueryResponse message is the successful response by the TEEP Agent after 
receiving a QueryRequest message. 

Like other TEEP messages, the QueryResponse message is
signed, and the relevant CDDL snippet is shown below. 
The complete CDDL structure is shown in {{CDDL}}.

~~~~
query-response = [
  type: TEEP-TYPE-query-response,
  options: {
    ? token => uint,
    ? selected-cipher-suite => suite,
    ? selected-version => version,
    ? evidence-format => text,
    ? evidence => bstr,
    ? tc-list => [ + tc-info ],
    ? requested-tc-list => [ + requested-tc-info ],
    ? unneeded-tc-list => [ + SUIT_Component_Identifier ],
    ? ext-list => [ + ext-info ],
    * $$query-response-extensions,
    * $$teep-option-extensions
  }
]

tc-info = {
  component-id => SUIT_Component_Identifier,
  ? tc-manifest-sequence-number => uint
}

requested-tc-info = {
  component-id => SUIT_Component_Identifier,
  ? tc-manifest-sequence-number => uint,
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

selected-cipher-suite
: The selected-cipher-suite parameter indicates the selected ciphersuite. Details
  about the ciphersuite encoding can be found in {{ciphersuite}}.

selected-version
: The selected-version parameter indicates the TEEP protocol version selected by the
  TEEP Agent. The absense of this parameter indicates the same as if it
  was present with a value of 0.

evidence-format
: The evidence-format parameter indicates the IANA Media Type of the
  attestation evidence contained in the evidence parameter.  It MUST be
  present if the evidence parameter is present and the format is not an EAT.

evidence
: The evidence parameter contains the attestation evidence.  This parameter
  MUST be present if the QueryResponse is sent in response to a QueryRequest
  with the attestation bit set.  If the evidence-format parameter is absent,
  the attestation evidence contained in this parameter MUST be
  an Entity Attestation Token following the encoding
  defined in {{I-D.ietf-rats-eat}}.

tc-list
: The tc-list parameter enumerates the Trusted Components installed on the device
  in the form of tc-info objects.  This parameter MUST be present if the
  QueryResponse is sent in response to a QueryRequest with the
  trusted-components bit set.

requested-tc-list
: The requested-tc-list parameter enumerates the Trusted Components that are
  not currently installed in the TEE, but which are requested to be installed,
  for example by an installer of an Untrusted Application that has a TA
  as a dependency, or by a Trusted Application that has another Trusted
  Component as a dependency.  Requested Trusted Components are expressed in
  the form of requested-tc-info objects.

unneeded-tc-list
: The unneeded-tc-list parameter enumerates the Trusted Components that are
  currently installed in the TEE, but which are no longer needed by any
  other application.  The TAM can use this information in determining
  whether a Trusted Component can be deleted.  Each unneeded Trusted Component is identified
  by its SUIT Component Identifier.

ext-list
: The ext-list parameter lists the supported extensions. This document does not
  define any extensions.

The tc-info object has the following fields:

{: vspace='0'}

component-id
: A SUIT Component Identifier.

tc-manifest-sequence-number
: The suit-manifest-sequence-number value from the SUIT manifest for the Trusted Component,
  if a SUIT manifest was used.

The requested-tc-info message has the following fields:

{: vspace='0'}

component-id
: A SUIT Component Identifier.

tc-manifest-sequence-number
: The minimum suit-manifest-sequence-number value from a SUIT manifest for
  the Trusted Component.  If not present, indicates that any version will do.

have-binary
: If present with a value of true, indicates that the TEEP agent already has
  the Trusted Component binary and only needs an Install message with a SUIT manifest
  that authorizes installing it.  If have-binary is true, the
  tc-manifest-sequence-number field MUST be present.

## Install Message

The Install message is used by the TAM to install a Trusted
Component via the TEEP Agent. 

Like other TEEP messages, the Install message is
signed, and the relevant CDDL snippet is shown below. 
The complete CDDL structure is shown in {{CDDL}}.

~~~~
install = [
  type: TEEP-TYPE-install,
  options: {
    ? token => uint,
    ? manifest-list => [ + bstr .cbor SUIT_Envelope ],
    * $$install-extensions,
    * $$teep-option-extensions
  }
]
~~~~

The Install message has the following fields:

{: vspace='0'}
type
: The value of (3) corresponds to an Install message sent from the TAM to
  the TEEP Agent. In case of successful processing, a Success
  message is returned by the TEEP Agent. In case of an error, an Error message
  is returned. Note that the Install message
  is used for initial Trusted Component installation as well as for updates.

token
: The value in the token field is used to match responses to requests.

manifest-list
: The manifest-list field is used to convey one or multiple SUIT manifests.
  A manifest is
  a bundle of metadata about a TA, such as where to
  find the code, the devices to which it applies, and cryptographic
  information protecting the manifest. The manifest may also convey personalization
  data. TA binaries and personalization data can be signed and encrypted
  by the same TA Signer. Other combinations are, however, possible as well. For example,
  it is also possible for the TAM to sign and encrypt the personalization data
  and to let the TA Developer sign and/or encrypt the TA binary.

## Delete Message

The Delete message is used by the TAM to remove a Trusted
Component from the device. 

Like other TEEP messages, the Delete message is
signed, and the relevant CDDL snippet is shown below. 
The complete CDDL structure is shown in {{CDDL}}.

~~~~
delete = [
  type: TEEP-TYPE-delete,
  options: {
  option: {
    ? token => uint,
    ? tc-list => [ + bstr ],
    ? tc-list => [ + SUIT_Component_Identifier ],
    * $$delete-extensions,
    * $$teep-option-extensions
  }
]
~~~~

The Delete message has the following fields:

{: vspace='0'}
type
: The value of (4) corresponds to a Delete message sent from the TAM to the
  TEEP Agent. In case of successful processing, a Success
  message is returned by the TEEP Agent. In case of an error, an Error message
  is returned.

token
: The value in the token parameter is used to match responses to requests.

tc-list
: The tc-list parameter enumerates the Trusted Components to be deleted,
  in the form of SUIT Component Identifiers.

## Success Message

The TEEP protocol defines two implicit success messages and this explicit 
Success message for the cases where the TEEP Agent cannot return another reply, 
such as for the Install and the Delete messages. 

Like other TEEP messages, the Success message is
signed, and the relevant CDDL snippet is shown below. 
The complete CDDL structure is shown in {{CDDL}}.

~~~~
teep-success = [
  type: TEEP-TYPE-teep-success,
  options: {
    ? token => uint,
    ? msg => text,
    ? suit-reports => [ + suit-report ],
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
  It MUST match the value of the token parameter in the Install or Delete
  message the Success is in response to, if one was present.  If none was
  present, the token MUST be absent in the Success message.

msg
: The msg parameter contains optional diagnostics information encoded in
  UTF-8 {{RFC3629}} returned by the TEEP Agent.

suit-reports
: If present, the suit-reports parameter contains a set of SUIT Reports
  as defined in Section 4 of {{I-D.moran-suit-report}}.

## Error Message

The Error message is used by the TEEP Agent to return an error. 

Like other TEEP messages, the Error message is
signed, and the relevant CDDL snippet is shown below. 
The complete CDDL structure is shown in {{CDDL}}.

~~~~
teep-error = [
  type: TEEP-TYPE-teep-error,
  options: {
     ? token => uint,
     ? err-msg => text,
     ? supported-cipher-suites => [ + suite ],
     ? versions => [ + version ],
     ? suit-reports => [ + suit-report ],
     * $$teep-error-extensions,
     * $$teep-option-extensions
  },
  err-code: uint
]
~~~~

The Error message has the following fields:

{: vspace='0'}
type
: The value of (6) corresponds to an Error message sent from the TEEP Agent to the TAM.

token
: The value in the token parameter is used to match responses to requests.
  It MUST match the value of the token parameter in the Install or Delete
  message the Success is in response to, if one was present.  If none was
  present, the token MUST be absent in the Error message.

err-msg
: The err-msg parameter is human-readable diagnostic text that MUST be encoded
  using UTF-8 {{RFC3629}} using Net-Unicode form {{RFC5198}}.

supported-cipher-suites
: The supported-cipher-suites parameter lists the ciphersuite(s) supported by the TEEP Agent.
  Details about the ciphersuite encoding can be found in {{ciphersuite}}.
  This field is optional but MUST be returned with the ERR_UNSUPPORTED_CRYPTO_ALG
  error message.

versions
: The versions parameter enumerates the TEEP protocol version(s) supported by the TEEP
  Agent. This otherwise optional parameter MUST be returned with the ERR_UNSUPPORTED_MSG_VERSION
  error message.

suit-reports
: If present, the suit-reports parameter contains a set of SUIT Reports
  as defined in Section 4 of {{I-D.moran-suit-report}}.

err-code
: The err-code parameter contains one of the values listed in the registry
  defined in {{error-code-registry}} (with the
  initial set of error codes listed below). Only selected values are applicable
  to each message.

This specification defines the following initial error messages:

{: vspace='0'}
ERR_ILLEGAL_PARAMETER (1)
: The TEEP 
  request contained incorrect fields or fields that are inconsistent with
  other fields.

ERR_UNSUPPORTED_EXTENSION (2)
: The TEEP Agent does not support the request message or
  an extension it indicated.

ERR_REQUEST_SIGNATURE_FAILED (3)
: The TEEP Agent
  could not verify the signature of the request message.

ERR_UNSUPPORTED_MSG_VERSION (4)
: The TEEP Agent does not
  support the TEEP protocol version indicated in the request message.

ERR_UNSUPPORTED_CRYPTO_ALG (5)
: The TEEP Agent does not
  support the cryptographic algorithm indicated in the request message.

ERR_BAD_CERTIFICATE (6)
: Processing of a certificate failed. For diagnosis purposes it is
  RECOMMMENDED to include information about the failing certificate
  in the error message.

ERR_UNSUPPORTED_CERTIFICATE (7)
: A certificate was of an unsupported type.

ERR_CERTIFICATE_REVOKED (8)
: A certificate was revoked by its signer.

ERR_CERTIFICATE_EXPIRED (9)
: A certificate has expired or is not currently
  valid.

ERR_INTERNAL_ERROR (10)
: A miscellaneous
  internal error occurred while processing the request message.

ERR_TC_NOT_FOUND (12)
: The target Trusted Component does not
  exist. This error may happen when the TAM has stale information and
  tries to delete a Trusted Component that has already been deleted.

ERR_MANIFEST_PROCESSING_FAILED (17)
: The TEEP Agent encountered one or more manifest processing failures.
  If the suit-reports parameter is present, it contains the failure details.

Additional error codes can be registered with IANA.

# Mapping of TEEP Message Parameters to CBOR Labels {#tags}

In COSE, arrays and maps use strings, negative integers, and unsigned
integers as their keys. Integers are used for compactness of
encoding. Since the word "key" is mainly used in its other meaning, as a
cryptographic key, this specification uses the term "label" for this usage
as a map key.

This specification uses the following mapping:

| Name                        | Label |
| supported-cipher-suites     |     1 |
| challenge                   |     2 |
| version                     |     3 |
| ocsp-data                   |     4 |
| selected-cipher-suite       |     5 |
| selected-version            |     6 |
| evidence                    |     7 |
| tc-list                     |     8 |
| ext-list                    |     9 |
| manifest-list               |    10 |
| msg                         |    11 |
| err-msg                     |    12 |
| evidence-format             |    13 |
| requested-tc-list           |    14 |
| unneeded-tc-list            |    15 |
| component-id                |    16 |
| tc-manifest-sequence-number |    17 |
| have-binary                 |    18 |
| suit-reports                |    19 |
| token                       |    20 |

# Ciphersuites {#ciphersuite}

A ciphersuite consists of an AEAD algorithm, an HMAC algorithm, and a signature
algorithm.
Each ciphersuite is identified with an integer value, which corresponds to
an IANA registered
ciphersuite (see {{ciphersuite-registry}}. This document specifies two ciphersuites.

| Value | Ciphersuite                                    |
|     1 | AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA |
|     2 | AES-CCM-16-64-128, HMAC 256/256, P-256, ES256  |

A TAM MUST support both ciphersuites.  A TEEP Agent MUST support at least
one of the two but can choose which one.  For example, a TEEP Agent might
choose ciphersuite 2 if it has hardware support for it.

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
: A TAM can rely on the attestation evidence provided by the TEEP
  Agent.  To sign the attestation evidence, it is necessary
  for the device to possess a public key (usually in the form of a
  certificate) along with the corresponding private key. Depending on
  the properties of the attestation mechanism, it is possible to
  uniquely identify a device based on information in the attestation
  evidence or in the certificate used to sign the attestation
  evidence.  This uniqueness may raise privacy concerns. To lower the
  privacy implications the TEEP Agent MUST present its attestation
  evidence only to an authenticated and authorized TAM and when using
  EATS, it SHOULD use encryption as discussed in {{I-D.ietf-rats-eat}}, since
  confidentiality is not provided by the TEEP protocol itself and
  the transport protocol under the TEEP protocol might be implemented
  outside of any TEE. If any mechanism other than EATs is used, it is
  up to that mechanism to specify how privacy is provided.

TA Binaries
: Each TA binary is signed by a TA Signer. It is the responsibility of the
  TAM to relay only verified TAs from authorized TA Signers.  Delivery of
  a TA to the TEEP Agent is then the responsibility of the TAM,
  using the security mechanisms provided by the TEEP
  protocol.  To protect the TA binary, the SUIT manifest format is used and
  it offers a variety of security features, including digitial
  signatures and symmetric encryption.

Personalization Data
: A TA Signer or TAM can supply personalization data along with a TA.
  This data is also protected by a SUIT manifest.
  Personalization data signed and encrypted by a TA Signer other than
  the TAM is opaque to the TAM.

TEEP Broker
: As discussed in section 6 of {{I-D.ietf-teep-architecture}},
  the TEEP protocol typically relies on a TEEP Broker to relay messages
  between the TAM and the TEEP Agent.  When the TEEP Broker is
  compromised it can drop messages, delay the delivery of messages,
  and replay messages but it cannot modify those messages. (A replay
  would be, however, detected by the TEEP Agent.) A compromised TEEP
  Broker could reorder messages in an attempt to install an old
  version of a TA. Information in the manifest ensures that TEEP
  Agents are protected against such downgrade attacks based on
  features offered by the manifest itself.

TA Signer Compromise
: The QueryRequest message from a TAM to the TEEP Agent can include
  OCSP stapling data for the TAM's certificate and for
  intermediate CA certificates up to the root certificate so that the
  TEEP Agent can verify the certificate's revocation status.  A
  certificate revocation status check on a TA Signer certificate is
  OPTIONAL by a TEEP Agent. A TAM is responsible for vetting a TA and
  before distributing them to TEEP Agents, so TEEP Agents can instead
  simply trust that a TA Signer certificate's status was done by the TAM.

CA Compromise
: The CA issuing certificates to a TAM or a TA Signer might get compromised.
  A compromised intermediate CA certificate can be detected by a TEEP
  Agent by using OCSP information, assuming the revocation information
  is available.  Additionally, it is RECOMMENDED to provide a way to
  update the trust anchor store used by the TEE, for example using
  a firmware update mechanism. If the CA issuing certificates to
  devices gets compromised then these devices might be rejected by a
  TAM, if revocation is available to the TAM.

Compromised TAM
: The TEEP Agent SHOULD use OCSP information to verify the validity of
  the TAM's certificate (as well as the validity of
  intermediate CA certificates). The integrity and the accuracy of the
  clock within the TEE determines the ability to determine an expired
  or revoked certificate. OCSP stapling data includes signature
  generation time, allowing certificate validity dates to be compared to the
  current time.

Compromised Time Source
: As discussed above, certificate validity checks rely on comparing
  validity dates to the current time, which relies on having a trusted
  source of time, such as {{RFC8915}}.  A compromised time source could
  thus be used to subvert such validity checks.

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
  considerations of application/cbor as specified in {{RFC7049}}.

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



## Error Code Registry {#error-code-registry}

IANA is also requested to create a new registry for the error codes defined
in {{detailmsg}}.

Registration requests are evaluated after a
three-week review period on the teep-reg-review@ietf.org mailing list,
on the advice of one or more Designated Experts {{RFC8126}}.  However,
to allow for the allocation of values prior to publication, the
Designated Experts may approve registration once they are satisfied
that such a specification will be published.

Registration requests sent to the mailing list for review should use
an appropriate subject (e.g., "Request to register an error code: example").
Registration requests that are undetermined for a period longer than
21 days can be brought to the IESG's attention (using the
iesg@ietf.org mailing list) for resolution.

Criteria that should be applied by the Designated Experts includes
determining whether the proposed registration duplicates existing
functionality, whether it is likely to be of general applicability or
whether it is useful only for a single extension, and whether the
registration description is clear.

IANA must only accept registry updates from the Designated Experts
and should direct all requests for registration to the review mailing
list.


## Ciphersuite Registry {#ciphersuite-registry}

IANA is also requested to create a new registry for ciphersuites, as defined
in {{ciphersuite}}.


## CBOR Tag Registry

IANA is requested to register a CBOR tag in the "CBOR Tags" registry
for use with TEEP messages.

The registry contents is:

* CBOR Tag: TBD1

* Data Item: TEEP Message

* Semantics: TEEP Message, as defined in [[TBD: This RFC]]

* Reference: [[TBD: This RFC]]

* Point of Contact: TEEP working group (teep@ietf.org)




--- back


# A. Contributors {#Contributors}
{: numbered='no'}

We would like to thank Brian Witten (Symantec), Tyler Kim (Solacia), Nick Cook (Arm), and  Minho Yoo (IoTrust) for their contributions
to the Open Trust Protocol (OTrP), which influenced the design of this specification.

# B. Acknowledgements {#Acknowledgements}
{: numbered='no'}

We would like to thank Eve Schooler for the suggestion of the protocol name.

We would like to thank Kohei Isobe (TRASIO/SECOM),
Kuniyasu Suzaki (TRASIO/AIST), Tsukasa Oi (TRASIO), and Yuichi Takita (SECOM)
for their valuable implementation feedback.

We would also like to thank Carsten Bormann and Henk Birkholz for their help with the CDDL. 

# C. Complete CDDL {#CDDL}
{: numbered='no'}

Valid TEEP messages MUST adhere to the following CDDL data definitions,
except that `SUIT_Envelope` and `SUIT_Component_Identifier` are
specified in {{I-D.ietf-suit-manifest}}.

~~~~
teep-message = $teep-message-type .within teep-message-framework

SUIT_Envelope = any

teep-message-framework = [
  type: 0..23 / $teep-type-extension,
  options: { * teep-option },
  * uint; further integers, e.g., for data-item-requested
]

teep-option = (uint => any)

; messages defined below:
$teep-message-type /= query-request
$teep-message-type /= query-response
$teep-message-type /= install
$teep-message-type /= delete
$teep-message-type /= teep-success
$teep-message-type /= teep-error

; message type numbers
TEEP-TYPE-query-request = 1
TEEP-TYPE-query-response = 2
TEEP-TYPE-install = 3
TEEP-TYPE-delete = 4
TEEP-TYPE-teep-success = 5
TEEP-TYPE-teep-error = 6

version = uint .size 4
ext-info = uint 

; data items as bitmaps
data-item-requested = $data-item-requested .within uint .size 8
attestation = 1
$data-item-requested /= attestation
trusted-components = 2
$data-item-requested /= trusted-components
extensions = 4
$data-item-requested /= extensions
suit-commands = 8
$data-item-requested /= suit-commands

query-request = [
  type: TEEP-TYPE-query-request,
  options: {
    ? token => uint,
    ? supported-cipher-suites => [ + suite ],
    ? challenge => bstr .size (8..64),
    ? versions => [ + version ],
    ? ocsp-data => bstr,
    * $$query-request-extensions
    * $$teep-option-extensions
  },
  data-item-requested: data-item-requested
]

; ciphersuites
suite = $TEEP-suite .within uint .size 4

TEEP-AES-CCM-16-64-128-HMAC256--256-X25519-EdDSA = 1
TEEP-AES-CCM-16-64-128-HMAC256--256-P-256-ES256  = 2

$TEEP-suite /= TEEP-AES-CCM-16-64-128-HMAC256--256-X25519-EdDSA
$TEEP-suite /= TEEP-AES-CCM-16-64-128-HMAC256--256-P-256-ES256

query-response = [
  type: TEEP-TYPE-query-response,
  options: {
    ? token => uint,
    ? selected-cipher-suite => suite,
    ? selected-version => version,
    ? evidence-format => text,
    ? evidence => bstr,
    ? tc-list => [ + tc-info ],
    ? requested-tc-list => [ + requested-tc-info ],
    ? unneeded-tc-list => [ + SUIT_Component_Identifier ],
    ? ext-list => [ + ext-info ],
    * $$query-response-extensions,
    * $$teep-option-extensions
  }
]

tc-info = {
  component-id => SUIT_Component_Identifier,
  ? tc-manifest-sequence-number => uint
}

requested-tc-info = {
  component-id => SUIT_Component_Identifier,
  ? tc-manifest-sequence-number => uint,
  ? have-binary => bool
}

install = [
  type: TEEP-TYPE-install,
  options: {
    ? token => uint,
    ? manifest-list => [ + bstr .cbor SUIT_Envelope ],
    * $$install-extensions,
    * $$teep-option-extensions
  }
]

delete = [
  type: TEEP-TYPE-delete,
  options: {
    ? token => uint,
    ? tc-list => [ + SUIT_Component_Identifier ],
    * $$delete-extensions,
    * $$teep-option-extensions
  }
]

teep-success = [
  type: TEEP-TYPE-teep-success,
  options: {
    ? token => uint,
    ? msg => text,
    ? suit-reports => [ + suit-report ],
    * $$teep-success-extensions,
    * $$teep-option-extensions
  }
]

teep-error = [
  type: TEEP-TYPE-teep-error,
  options: {
     ? token => uint,
     ? err-msg => text,
     ? supported-cipher-suites => [ + suite ],
     ? versions => [ + version ],
     ? suit-reports => [ + suit-report ],
     * $$teep-error-extensions,
     * $$teep-option-extensions
  },
  err-code: uint
]

supported-cipher-suites = 1
challenge = 2
versions = 3
ocsp-data = 4
selected-cipher-suite = 5
selected-version = 6
evidence = 7
tc-list = 8
ext-list = 9
manifest-list = 10
msg = 11
err-msg = 12
evidence-format = 13
requested-tc-list = 14
unneeded-tc-list = 15
component-id = 16
tc-manifest-sequence-number = 17
have-binary = 18
suit-reports = 19
token = 20
~~~~

# D. Examples of Diagnostic Notation and Binary Representation {#examples}
{: numbered='no'}

### Some assumptions in examples
{: numbered='no'}

- OCSP stapling data = h'010203'
- TEEP Device will have 2 TAs with the following SUIT Component Identifiers:
  - [ 0x0102030405060708090a0b0c0d0e0f ]
  - [ 0x1102030405060708090a0b0c0d0e0f ]
- SUIT manifest-list is set empty only for example purposes
- Not including Entity Attestation Token (EAT) parameters for example purposes

## QueryRequest Message
{: numbered='no'}

### CBOR Diagnostic Notation
{: numbered='no'}

~~~~
/ query-request = /
[
    1,          / type : TEEP-TYPE-query-request = 1 (fixed int) /
    / options : /
    {
        20 : 2004318071, / token : 0x77777777 (uint), generated by TAM /
        1 : [ 1 ], / supported-cipher-suites = 1 (mapkey) : /
                   / TEEP-AES-CCM-16-64-128-HMAC256--256-X25519-EdDSA =
                     [ 1 ] (array of uint .size 8) /
        3 : [ 0 ], / version = 3 (mapkey) : 
                     [ 0 ] (array of uint .size 4) /
        4 : h'010203' / ocsp-data = 4 (mapkey) : 0x010203 (bstr) /
    },
    2           / data-item-requested : trusted-components = 2 (uint) /
]
~~~~

### CBOR Binary Representation
{: numbered='no'}

~~~~
84                        # array(4), 
   01                     # unsigned(1)
   A4                     # map(4)
      14                  # unsigned(20)
      1A 77777777         # unsigned(2004318071, 0x77777777)
      01                  # unsigned(1)
      81                  # array(1)
         01               # unsigned(1) within .size 8
      03                  # unsigned(3)
      81                  # array(1)
         00               # unsigned(0) within .size 4
      04                  # unsigned(4)
      43                  # bytes(3)
         010203           # "\x01\x02\x03"
   02                     # unsigned(2)
~~~~

## QueryResponse Message
{: numbered='no'}

### CBOR Diagnostic Notation
{: numbered='no'}

~~~~
/ query-response = /
[
    2,          / type : TEEP-TYPE-query-response = 2 (fixed int) /
    / options : /
    {
        20 : 2004318071, / token : 0x77777777 (uint), from TAM's QueryRequest
                           message /
        5 : 1,  / selected-cipher-suite = 5(mapkey) :/
                / TEEP-AES-CCM-16-64-128-HMAC256--256-X25519-EdDSA = 
                      1 (uint .size 8) /
        6 : 0,  / selected-version = 6 (mapkey) : 0 (uint .size 4) /
        8 : [ [ h'0102030405060708090a0b0c0d0e0f' ],
              [ h'1102030405060708090a0b0c0d0e0f' ] ]
                / ta-list = 8 (mapkey) : 
                      [ [ 0x0102030405060708090a0b0c0d0e0f ],
                        [ 0x1102030405060708090a0b0c0d0e0f ] ]
                      (array of bstr) /
    }
]
~~~~

### CBOR Binary Representation
{: numbered='no'}

~~~~
83                        # array(3)
   02                     # unsigned(2)
   A4                     # map(4)
      14                  # unsigned(20)
      1A 77777777         # unsigned(2004318071, 0x77777777)
      05                  # unsigned(5)
      01                  # unsigned(1) within .size 8
      06                  # unsigned(6)
      00                  # unsigned(0) within .size 4
      08                  # unsigned(8)
      82                  # array(2)
         81               # array(1)
            4F            # bytes(16)
               0102030405060708090A0B0C0D0D0F
         81               # array(1)
            4F            # bytes(16)
               1102030405060708090A0B0C0D0D0F
~~~~

## Install Message
{: numbered='no'}

### CBOR Diagnostic Notation
{: numbered='no'}

~~~~
/ install = /
[
    3,          / type : TEEP-TYPE-install = 3 (fixed int) /
    / options :  /
    {
        20 : 2004318072, / token : 0x777777778 (uint), generated by TAM /
        10 : [ ] / manifest-list = 10 (mapkey) : 
                       [ ] (array of bstr wrapped SUIT_Envelope(any)) /
                 / empty, example purpose only /
    }
]
~~~~

### CBOR Binary Representation
{: numbered='no'}

~~~~
83                        # array(3)
   03                     # unsigned(3)
   A2                     # map(2)
      14                  # unsigned(20)
      1A 77777778         # unsigned(2004318072, 0x77777778)
      0A                  # unsigned(10)
      80                  # array(0)
~~~~

## Success Message (for Install)
{: numbered='no'}

### CBOR Diagnostic Notation
{: numbered='no'}

~~~~
/ teep-success = /
[
    5,          / type : TEEP-TYPE-teep-success = 5 (fixed int) /
    / options :  /
    {
        20 : 2004318072, / token : 0x777777778 (uint), from Install message /
    }
]
~~~~

### CBOR Binary Representation
{: numbered='no'}

~~~~
82                        # array(2)
    05                    # unsigned(5)
    A1                    # map(1)
    14                    # unsigned(20)
    1A 77777778           # unsigned(2004318072, 0x77777778)
~~~~


## Error Message (for Install)
{: numbered='no'}

### CBOR Diagnostic Notation
{: numbered='no'}

~~~~
/ teep-error = /
[
    6,          / type : TEEP-TYPE-teep-error = 6 (fixed int) /
    / options :  /
    {
        20 : 2004318072, / token : 0x777777778 (uint), from Install message /
        12 : "disk-full"  / err-msg = 12 (mapkey) : 
                                "disk-full" (UTF-8 string) /
    },
    ERR_MANIFEST_PROCESSING_FAILED
        / err-code : ERR_MANIFEST_PROCESSING_FAILED = 17 (uint) /
]
~~~~

### CBOR binary Representation
{: numbered='no'}

~~~~
84                        # array(4)
    06                    # unsigned(6)
    A1                    # map(1)
       14                 # unsigned(20)
       1A 77777778        # unsigned(2004318072, 0x77777778)
       0C                 # unsigned(12)
       69                 # text(9)
          6469736b2d66756c6c  # "disk-full"
    11                    # unsigned(17)
~~~~
