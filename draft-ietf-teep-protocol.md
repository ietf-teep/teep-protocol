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
- ins: H. Tschofenig
  name: Hannes Tschofenig
  org: Arm Ltd.
  street: ''
  city: Absam
  region: Tirol
  code: '6067'
  country: Austria
  email: hannes.tschofenig@arm.com
- ins: M. Pei
  name: Mingliang Pei
  org: Broadcom
  street: 350 Ellis St
  city: Mountain View
  region: CA
  code: '94043'
  country: USA
  email: mingliang.pei@broadcom.com
- ins: D. Wheeler
  name: David Wheeler
  org: Intel
  street: ''
  city: ''
  region: ''
  code: ''
  country: US
  email: david.m.wheeler@intel.com
- ins: D. Thaler
  name: Dave Thaler
  org: Microsoft
  street: ''
  city: ''
  region: ''
  code: ''
  country: US
  email: dthaler@microsoft.com
normative:
  RFC4648: 
  RFC8152: 
  RFC3629: 
  RFC5198: 
  RFC7049: 
  I-D.ietf-rats-eat: 
  I-D.ietf-suit-manifest: 
  RFC2560: 
informative:
  I-D.ietf-teep-architecture: 
  RFC8610: 
  RFC8126: 
  I-D.ietf-teep-opentrustprotocol: 

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
Environment (REE), from security-sensitive applications. In an TEE
ecosystem, device vendors may use different operating systems in the
REE and may use different types of TEEs. When application providers or
device administrators use Trusted Application Managers (TAMs) to
install, update, and delete Trusted Applications (TAs) on a wide range
of devices with potentially different TEEs then an interoperability
need arises.

This document specifies the protocol for communicating between a TAM
and a TEEP Agent, involving a TEEP Broker.

The Trusted Execution Environment Provisioning (TEEP) architecture
document {{I-D.ietf-teep-architecture}} has set to provide a design
guidance for such an interoperable protocol and introduces the
necessary terminology.  Note that the term Trusted Application may
include more than code; it may also include configuration data and
keys needed by the TA to operate correctly.


# Requirements Language

{::boilerplate bcp14}

This specification re-uses the terminology defined in {{I-D.ietf-teep-architecture}}.


# Message Overview {#messages}

The TEEP protocol consists of a couple of messages exchanged between a TAM
and a TEEP Agent via a TEEP Broker.
The messages are encoded in CBOR and designed to provide end-to-end security.
TEEP protocol messages are signed by the endpoints, i.e., the TAM and the
TEEP Agent, but trusted
applications may as well be encrypted and signed by the service provider.
The TEEP protocol not only re-use
CBOR but also the respective security wrapper, namely COSE {{RFC8152}}. Furthermore,
for attestation the Entity Attestation Token (EAT) {{I-D.ietf-rats-eat}} and for software updates the SUIT
manifest format {{I-D.ietf-suit-manifest}} are re-used.

This specification defines six messages.

A TAM queries a device's current state with a QueryRequest message.
A TEEP Agent will, after authenticating and authorizing the request, report
attestation information, list all TAs, and provide information about supported
algorithms and extensions in a QueryResponse message. An error message is
returned if the request
could not be processed. A TAM will process the QueryResponse message and
determine
whether subsequent message exchanges to install, update, or delete trusted
applications
shall be initiated.

~~~~
  +------------+           +-------------+
  | TAM        |           |TEEP Agent   |
  +------------+           +-------------+

    QueryRequest ------->

                           QueryResponse

                 <-------     or

                             Error
~~~~


With the TrustedAppInstall message a TAM can instruct a TEEP Agent to install
a TA.
The TEEP Agent will process the message, determine whether the TAM is authorized
and whether the
TA has been signed by an authorized SP. In addition to the binary, the TAM
may also provide
personalization data. If the TrustedAppInstall message was processed successfully
then a
Success message is returned to the TAM, an Error message otherwise.

~~~~
 +------------+           +-------------+
 | TAM        |           |TEEP Agent   |
 +------------+           +-------------+

   TrustedAppInstall ---->

                            Success

                    <----    or

                            Error
~~~~


With the TrustedAppDelete message a TAM can instruct a TEEP Agent to delete
one or multiple TA(s).
A Success message is returned when the operation has been completed successfully,
and an Error message
otherwise.

~~~~
 +------------+           +-------------+
 | TAM        |           |TEEP Agent   |
 +------------+           +-------------+

   TrustedAppDelete  ---->

                            Success

                    <----    or

                            Error
~~~~



# Detailed Messages Specification {#detailmsg}

TEEP messages are protected by the COSE_Sign1 structure.
The TEEP protocol messages are described in CDDL format {{RFC8610}} below.

~~~~
    teep-message                => (QueryRequest /
                                    QueryResponse /
                                    TrustedAppInstall /
                                    TrustedAppDelete /
                                    Error /
                                    Success ),
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




## QueryRequest



~~~~
suite = uint

version = uint

data_item = uint

QueryRequest = [
     type : uint,
     token : uint,
     request : [+data_item],
     {
        ? cipher_suite : [+suite],
        ? nonce : bstr,
        ? version : [+version],
        ? ocsp_data : bstr
     }
]
~~~~


A QueryRequest message is signed by the TAM and has the following fields:

{: vspace='0'}
type
: The value of (1) corresponds to a QueryRequest message sent from the TAM to 
  the TEEP Agent.

token
: The value in the token field is used to match responses to requests. This is 
useful when a TAM issues multiple concurrent requests to a TEEP Agent. 

request
: The request field indicates what information the TAM requests from the TEEP
  Agent in form of a list of unsigned integer values. Each unsigned integer 
  value corresponds to an IANA registered information element. This 
  specification defines the following initial set of information elements:

   attestation (1)
   : With this value the TAM requests the TEEP Agent to return an entity attestation
     token (EAT) in the response.

   trusted_apps (2)
   : With this value the TAM queries the TEEP Agent for all installed TAs.

   extensions (3)
   : With this value the TAM queries the TEEP Agent for supported capabilities
     and extensions, which allows a TAM to discover the capabilities of a TEEP
     Agent implementation.

   suit_commands (4)
   : With this value the TAM queries the TEEP Agent for supported commands offered
     by the SUIT manifest implementation.
  
   Further values may be added in the future via IANA registration.

cipher_suite
: The cipher_suite field lists the ciphersuite(s) supported by the TAM. Details
  about the ciphersuite encoding can be found in {{ciphersuite}}.

nonce
: The none field is an optional field used for ensuring the refreshness of the Entity
  Attestation Token (EAT) returned with a QueryResponse message. When a nonce is 
  provided in the QueryRequest and an EAT is returned with the QueryResponse message
  then the nonce contained in this request MUST be copied into the nonce claim found 
  in the EAT token. 

version
: The version field lists the version(s) supported by the TAM. For this version
  of the specification this field can be omitted.

ocsp_data
: The ocsp_data field contains a list of OCSP stapling data
  respectively for the TAM certificate and each of the CA certificates
  up to the root certificate.  The TAM provides OCSP data so that the
  TEEP Agent can validate the status of the TAM certificate chain
  without making its own external OCSP service call. OCSP data MUST be
  conveyed as a DER-encoded OCSP response (using the ASN.1 type
  OCSPResponse defined in {{RFC2560}}). The use of OCSP is optional to
  implement for both the TAM and the TEEP Agent. A TAM can query the
  TEEP Agent for the support of this functionality via the capability
  discovery exchange, as described above.


## QueryResponse

~~~~
ext_info = uint
ta_id = bstr

QueryResponse = [
     type : uint,
     token : uint,
     {
        ? selected_cipher_suite : suite,
        ? selected_version : version,
        ? eat : bstr,
        ? ta_list  : [+ta_id],
        ? ext_list : [+ext_info]
     }
]

~~~~

The QueryResponse message is signed and encrypted by the TEEP Agent and returned
to the TAM. It has the following fields:

{: vspace='0'}
type
: The value of (2) corresponds to a QueryResponse message sent from the TEEP Agent
  to the TAM.

token
: The value in the token field is used to match responses to requests. The
  value MUST correspond to the value received with the QueryRequest.


selected_cipher_suite
: The selected_cipher_suite field indicates the selected ciphersuite. Details
  about the ciphersuite encoding can be found in {{ciphersuite}}.

selected_version
: The selected_version field indicates the protocol version selected by the
  TEEP Agent.

eat
: The eat field contains an Entity Attestation Token following the encoding
  defined in {{I-D.ietf-rats-eat}}.

ta_list
: The ta_list field enumerates the trusted applications installed on the device
  in form of TA_ID byte strings.

ext_list
: The ext_list field lists the supported extensions. This document does not
  define any extensions.


## TrustedAppInstall

~~~~
TrustedAppInstall = ]
     type : uint,
     token : uint,
     {
         ? manifest_list  : [+ SUIT_Outer_Wrapper]
     }
]
~~~~

The TrustedAppInstall message has the following fields:

{: vspace='0'}
type
: The value of (3) corresponds to a TrustedAppInstall message sent from the TAM to
  the TEEP Agent. In case of successful processing, an Success
  message is returned by the TEEP Agent. In case of an error, an Error message
  is returned. Note that the TrustedAppInstall message
  is used for initial TA installation but also for TA updates.

token
: The value in the token field is used to match responses to requests.

manifest_list
: The manifest_list field is used to convey one or multiple SUIT manifests.
  A manifest is
  a bundle of metadata about the trusted app, where to
  find the code, the devices to which it applies, and cryptographic
  information protecting the manifest. The manifest may also convey personalization
  data. TA binaries and personalization data is typically signed and encrypted
  by the SP. Other combinations are, however, possible as well. For example,
  it is also possible for the TAM to sign and encrypt the personalization data
  and to let the SP sign and/or encrypt the TA binary.

## TrustedAppDelete

~~~~
TrustedAppDelete  = [
     TYPE : uint,
     token : uint,
     {
         ? ta_list  : [+ta_id]
     }
]
~~~~

The TrustedAppDelete message has the following fields:

{: vspace='0'}
type
: The value of (4) corresponds to a TrustedAppDelete message sent from the TAM to the
  TEEP Agent. In case of successful processing, an Success
  message is returned by the TEEP Agent. In case of an error, an Error message
  is returned.

token
: The value in the token field is used to match responses to requests.

ta_list
: The ta_list field enumerates the TAs to be deleted.


## Success

~~~~
Success = [
     type : uint,
     token : uint,
     {
        ? msg : tstr
     }
]
~~~~

The Success message has the following fields:

{: vspace='0'}
type
: The value of (5) corresponds to corresponds to a Success message sent from the TEEP Agent to the
  TAM.

token
: The value in the token field is used to match responses to requests.

msg
: The msg field contains optional diagnostics information encoded in
  UTF-8 {{RFC3629}} returned by the TEEP Agent.


## Error

~~~~
Error = [
     type : uint,
     token : uint,
     error_code : uint,
     {
        ? err_msg : tstr,
        ? cipher_suite : [+suite],
        ? version : [+version]
     }
]
~~~~

The Error message has the following fields:

{: vspace='0'}
type
: The value of (6) corresponds to an Error message sent from the TEEP Agent to the TAM.

token
: The value in the token field is used to match responses to requests.

err_code
: The err_code field is populated with values listed in a registry (with the
  initial set of error codes listed below). Only selected messages are applicable
  to each message.

err_msg
: The err_msg message is a human-readable diagnostic message that MUST be encoded
  using UTF-8 {{RFC3629}} using Net-Unicode form {{RFC5198}}.

version
: The version field enumerates the protocol version(s) supported by the TEEP
  Agent. This field is optional but MUST be returned with the ERR_UNSUPPORTED_MSG_VERSION
  error message.

cipher_suite
: The cipher_suite field lists the ciphersuite(s) supported by the TEEP Agent.
  This field is optional but MUST be returned with the ERR_UNSUPPORTED_CRYPTO_ALG
  error message.

This specification defines the following initial error messages:

{: vspace='0'}
ERR_ILLEGAL_PARAMETER (1)
: The TEEP Agent sends this error message when
  a request contains incorrect fields or fields that are inconsistent with
  other fields.

ERR_UNSUPPORTED_EXTENSION (2)
: The TEEP Agent sends this error message when
  it recognizes an unsupported extension or unsupported message.

ERR_REQUEST_SIGNATURE_FAILED (3)
: The TEEP Agent sends this error message when
  it fails to verify the signature of the message.

ERR_UNSUPPORTED_MSG_VERSION (4)
: The TEEP Agent receives a message but does not
  support the indicated version.

ERR_UNSUPPORTED_CRYPTO_ALG (5)
: The TEEP Agent receives a request message
  encoded with an unsupported cryptographic algorithm.

ERR_BAD_CERTIFICATE (6)
: The TEEP Agent returns this error
  when processing of a certificate failed. For diagnosis purposes it is
  RECOMMMENDED to include information about the failing certificate
  in the error message.

ERR_UNSUPPORTED_CERTIFICATE (7)
: The TEEP Agent returns this error
  when a certificate was of an unsupported type.

ERR_CERTIFICATE_REVOKED (8)
: The TEEP Agent returns this error
  when a certificate was revoked by its signer.

ERR_CERTIFICATE_EXPIRED (9)
: The TEEP Agent returns this error
  when a certificate has expired or is not currently
  valid.

ERR_INTERNAL_ERROR (10)
: The TEEP Agent returns this error when a miscellaneous
  internal error occurred while processing the request.

ERR_RESOURCE_FULL (11)
: This error is reported when a device
  resource isn't available anymore, such as storage space is full.

ERR_TA_NOT_FOUND (12)
: This error will occur when the target TA does not
  exist. This error may happen when the TAM has stale information and
  tries to delete a TA that has already been deleted.

ERR_TA_ALREADY_INSTALLED (13)
: While installing a TA, a TEE will return
  this error if the TA has already been installed.

ERR_TA_UNKNOWN_FORMAT (14)
: The TEEP Agent returns this error when
  it does not recognize the format of the TA binary.

ERR_TA_DECRYPTION_FAILED (15)
: The TEEP Agent returns this error when
  it fails to decrypt the TA binary.

ERR_TA_DECOMPRESSION_FAILED (16)
: The TEEP Agent returns this error when
  it fails to decompress the TA binary.

ERR_MANIFEST_PROCESSING_FAILED (17)
: The TEEP Agent returns this error when
  manifest processing failures occur that are less specific than
  ERR_TA_UNKNOWN_FORMAT, ERR_TA_UNKNOWN_FORMAT, and ERR_TA_DECOMPRESSION_FAILED.

ERR_PD_PROCESSING_FAILED (18)
: The TEEP Agent returns this error when
  it fails to process the provided personalization data.

Additional error code can be registered with IANA.

# Mapping of TEEP Message Parameters to CBOR Labels {#tags}

In COSE, maps use strings, negative integers, and unsigned
integers as map keys. Integers are used for compactness of
encoding. Since the word "key" is mainly used in its other meaning, as a
cryptographic key, this specification uses the term "label" for this usage
as a map
key.

This specification uses the following tags for protocol fields.

| Name                  | Label |
| cipher\_suite         |     1 |
| nonce                 |     2 |
| version               |     3 |
| ocsp_data             |     4 |
| selected\_ciphersuite |     5 |
| selected\_version     |     6 |
| eat                   |     7 |
| ta\_list              |     8 |
| ext\_list             |     9 |
| manifest\_list        |    10 |
| err\_msg              |    11 |


# Ciphersuites {#ciphersuite}

A ciphersuite consists of an AEAD algorithm, a HMAC algorithm, and a signature
algorithm.
Each ciphersuite is identified with an integer value, which corresponds to
an IANA registered
ciphersuite. This document specifies two ciphersuites.

| Value | Ciphersuite                                    |
|     0 | AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA |
|     1 | AES-CCM-16-64-128, HMAC 256/256, P-256, ES256  |

# Security Considerations {#security}

This section summarizes the security considerations discussed in this
specification:

{: vspace='0'}
Cryptographic Algorithms
: TEEP protocol messages exchanged between the TAM and the TEEP Agent
  are protected using COSE. This specification relies on the
  cryptographic algorithms provided by COSE.  Public key based
  authentication is used to by the TEEP Agent to authenticate the TAM
  and vice versa.

Attestation
: A TAM may rely on the attestation information provided by the TEEP
  Agent and the Entity Attestation Token is re-used to convey this
  information. To sign the Entity Attestation Token it is necessary
  for the device to possess a public key (usually in the form of a
  certificate) along with the corresponding private key. Depending on
  the properties of the attestation mechanism it is possible to
  uniquely identify a device based on information in the attestation
  information or in the certificate used to sign the attestation
  token.  This uniqueness may raise privacy concerns. To lower the
  privacy implications the TEEP Agent MUST present its attestation
  information only to an authenticated and authorized TAM.

TA Binaries
: TA binaries are provided by the SP.It is the responsibility of the
  TAM to relay only verified TAs from authorized SPs.  Delivery of
  that TA to the TEEP Agent is then the responsibility of the TAM and
  the TEEP Broker, using the security mechanisms provided by the TEEP
  protocol.  To protect the TA binary the SUIT manifest is re-used and
  it offers a varity of security features, including digitial
  signatures and symmetric encryption.

Personalization Data
: An SP or a TAM can supply personalization data along with a TA.
  This data is also protected by a SUIT manifest.
  The personalization data may be opaque to the TAM.

TEEP Broker
: The TEEP protocol relies on the TEEP Broker to relay messages
  between the TAM and the TEEP Agent.  When the TEEP Broker is
  compromised it can drop messages, delay the delivery of messages,
  and replay messages but it cannot modify those messages. (A replay
  would be, however, detected by the TEEP Agent.) A compromised TEEP
  Broker could reorder messages in an attempt to install an old
  version of a TA. Information in the manifest ensures that the TEEP
  Agents are protected against such downgrading attacks based on
  features offered by the manifest itself.

CA Compromise
: The QueryRequest message from a TAM to the TEEP Agent may include
  OCSP stapling data for the TAM's signer certificate and for
  intermediate CA certificates up to the root certificate so that the
  TEEP Agent can verify the certificate's revocation status.  A
  certificate revocation status check on a TA signer certificate is
  OPTIONAL by a TEEP Agent. A TAM is responsible for vetting a TA and
  before distributing them to TEEP Agents. TEEP Agents will trust a TA
  signer certificate's validation status done by a TAM.

CA Compromise
: The CA issuing certificates to a TAM or an SP may get compromised.
  A compromised intermediate CA certificates can be detected by a TEEP
  Agent by using OCSP information, assuming the revocation information
  is available.  Additionally, it is RECOMMENDED to provide a way to
  update the trust anchor store used by the device, for example using
  a firmware update mechanism. If the CA issuing certificates to
  devices gets compromised then these devices might be rejected by a
  TAM, if revocation is available to the TAM.

Compromised TAM
: The TEEP Agent SHOULD use OCSP information to verify the validity of
  the TAM-provided certificate (as well as the validity of
  intermediate CA certificates). The integrity and the accuracy of the
  clock within the TEE determines the ability to determine an expired
  or revoked certificate since OCSP stapling includes signature
  generation time, certificate validity dates are compared to the
  current time.




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
  application/cbor

Security considerations:
: See Security Considerations Section of this document.

Interoperability considerations:
: Same as interoperability
  considerations of application/cbor as specified in {{RFC7049}}

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



## Error Code Registry

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


## Ciphersuite Registry

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


# Contributors {#Contributors}
{: numbered='no'}

We would like to thank the following individuals for their contributions
to an initial version
of this specification.


~~~~
- Brian Witten
  Symantec
  brian_witten@symantec.com

- Tyler Kim
  Solacia
  tylerkim@iotrust.kr

- Nick Cook
  Arm Ltd.
  nicholas.cook@arm.com

- Minho Yoo
  IoTrust
  minho.yoo@iotrust.kr
~~~~


# Acknowledgements {#Acknowledgements}
{: numbered='no'}

This work is based on the initial version of OTrP {{I-D.ietf-teep-opentrustprotocol}} and hence credits
go to those who have contributed to it.

We would like to thank Eve Schooler for the suggestion of the protocol name.

We would like to thank Akira Tsukamoto (AIST), Kohei Isobe (TRASIO/SECOM),
Kuniyasu Suzaki (TRASIO/AIST), Tsukasa Oi (TRASIO), and Yuichi Takita (SECOM)
for their valuable implementation feedback.

Thanks to Carsten Bormann for helping us with the CDDL. 
