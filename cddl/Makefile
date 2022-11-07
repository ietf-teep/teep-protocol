MESSAGES := ../cbor/query_request.diag.bin ../cbor/query_response.diag.bin ../cbor/update.diag.bin ../cbor/teep_success.diag.bin ../cbor/teep_error.diag.bin

CONCATENATED_TEEP_PROTOCOL_CDDL	:= check-draft-ietf-teep-protocol.cddl
CONCATENATED_SUIT_MANIFEST_CDDL	:= check-draft-ietf-suit-manifest.cddl

TEEP_PROTOCOL_CDDL		:= ../draft-ietf-teep-protocol.cddl
SUIT_MANIFEST_CDDL		:= draft-ietf-suit-manifest.cddl
SUIT_TRUST_DOMAINS_CDDL	:= draft-ietf-trust-domains.cddl
SUIT_REPORT_CDDL		:= draft-ietf-suit-report.cddl
COSE_XML			:= rfc-8152-cose.xml
COSE_CDDL			:= rfc-8152-cose.cddl
WORKAROUND_DEPENDENCY		:= workaround_dependency.cddl

CDDLS				:= $(TEEP_PROTOCOL_CDDL)
CDDLS				+= $(CONCATENATED_SUIT_MANIFEST_CDDL) $(SUIT_REPORT_CDDL)
#CDDLS				+= $(WORKAROUND_DEPENDENCY)

.PHONY: all validate clean

all: $(CONCATENATED_TEEP_PROTOCOL_CDDL)

$(MESSAGES):
	make -C ../cbor

$(CONCATENATED_TEEP_PROTOCOL_CDDL): $(CDDLS)
	cat $^ > $@

$(CONCATENATED_SUIT_MANIFEST_CDDL): $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(COSE_CDDL)
	cat $^ > $@

$(SUIT_MANIFEST_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/manifest-spec/master/draft-ietf-suit-manifest.cddl -o $@

$(SUIT_TRUST_DOMAINS_CDDL):
	curl https://raw.githubusercontent.com/bremoran/suit-multiple-trust-domains/f/component-id/draft-ietf-suit-trust-domains.cddl -o $@

$(SUIT_REPORT_CDDL):
	curl https://raw.githubusercontent.com/bremoran/suit-report/main/draft-ietf-suit-report.cddl -o $@

$(COSE_XML):
	curl https://www.ietf.org/archive/id/draft-ietf-cose-msg-24.xml -o $@

$(COSE_CDDL): $(COSE_XML)
	sed -n -e '/<artwork type="CDDL"/,/<\/artwork/ p' $< | sed -e '/<artwork type="CDDL"/ d' -e '/<\/artwork/ d' -e '/<\/section>/,/<figure title=""/ d' -e 's/\&gt;/>/g' -e 's/\r$$//g' > $@

validate: all $(MESSAGES)
	$(foreach msg,$(MESSAGES),cddl $(CONCATENATED_TEEP_PROTOCOL_CDDL) validate $(msg) || echo "$(msg) is illegal";)

clean:
	$(RM) $(CONCATENATED_TEEP_PROTOCOL_CDDL) $(CONCATENATED_SUIT_MANIFEST_CDDL) $(COSE_XML) $(COSE_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(SUIT_REPORT_CDDL)
