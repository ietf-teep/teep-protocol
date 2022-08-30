MESSAGES := ../cbor/query_request.tcbor ../cbor/query_response.tcbor ../cbor/update.tcbor ../cbor/teep_success.tcbor ../cbor/teep_error.tcbor

CONCATENATED_CDDL	:= check-draft-ietf-teep-protocol.cddl
DUMMY_CDDL			:= dummy.cddl
TEEP_PROTOCOL_CDDL	:= ../draft-ietf-teep-protocol.cddl
SUIT_MANIFEST_CDDL	:= draft-ietf-suit-manifest.cddl
SUIT_REPORT_MD		:= draft-ietf-suit-report.md
SUIT_REPORT_CDDL	:= draft-ietf-suit-report.cddl
COSE_CDDL			:= rfc-8152-cose.cddl

CDDLS				:= $(TEEP_PROTOCOL_CDDL)
CDDLS				+= $(DUMMY_CDDL)
#CDDLS				+= $(COSE_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_REPORT_CDDL) # WIP

.PHONY: all validate clean

all: $(CONCATENATED_CDDL)

$(MESSAGES):
	make -C ../cddl

$(CONCATENATED_CDDL): $(CDDLS)
	cat $^ > $@

$(SUIT_MANIFEST_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/manifest-spec/master/draft-ietf-suit-manifest.cddl -o $@

$(SUIT_REPORT_MD):
	curl https://raw.githubusercontent.com/bremoran/suit-report/main/draft-ietf-suit-report.md -o $@

$(SUIT_REPORT_CDDL): $(SUIT_REPORT_MD)
	sed -n '/^\~\~\~/,/^\~\~\~/ p' < $^ | sed '/\~\~\~/ d' > $@

$(COSE_CDDL):
	curl https://raw.githubusercontent.com/EricssonResearch/EDHOC/master/cose.cddl -o $@
	sed -i -e 's/\x1a//g' $@

validate: all $(MESSAGES)
	$(foreach msg,$(MESSAGES),cddl $(CONCATENATED_CDDL) validate $(msg) || exit 1;)

clean:
	$(RM) $(CONCATENATED_CDDL) $(COSE_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_REPORT_CDDL) $(SUIT_REPORT_MD)
