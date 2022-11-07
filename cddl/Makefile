TEEP_MESSAGES	:= ../cbor/query_request.diag.bin ../cbor/query_response.diag.bin ../cbor/update.diag.bin ../cbor/teep_success.diag.bin ../cbor/teep_error.diag.bin
SUIT_MANIFESTS	:= ../cbor/suit_uri.diag.bin ../cbor/suit_integrated.diag.bin ../cbor/suit_personalization.diag.bin ../cbor/suit_unlink.diag.bin

CONCATENATED_CDDL	:= check-draft-ietf-teep-protocol.cddl
CONCATENATED_UNTAGGED_SUIT_MANIFEST_CDDL	:= check-draft-ietf-suit-manifest.cddl

TEEP_PROTOCOL_CDDL		:= ../draft-ietf-teep-protocol.cddl
SUIT_MANIFEST_SHIM_CDDL	:= suit-manifest-shim.cddl
SUIT_MANIFEST_CDDL		:= draft-ietf-suit-manifest.cddl
SUIT_TRUST_DOMAINS_CDDL	:= draft-ietf-trust-domains.cddl
SUIT_REPORT_CDDL		:= draft-ietf-suit-report.cddl
COSE_XML			:= rfc-8152-cose.xml
COSE_CDDL			:= rfc-8152-cose.cddl

CDDLS				:= $(TEEP_PROTOCOL_CDDL)
CDDLS				+= $(COSE_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(SUIT_REPORT_CDDL)

.PHONY: cat-cddl
cat-cddl: $(CONCATENATED_CDDL) $(CONCATENATED_UNTAGGED_SUIT_MANIFEST_CDDL)

$(CONCATENATED_CDDL): $(CDDLS)
	cat $(CDDLS) > $@

$(CONCATENATED_UNTAGGED_SUIT_MANIFEST_CDDL): $(SUIT_MANIFEST_SHIM_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(SUIT_REPORT_CDDL) $(COSE_CDDL)
	cat $^ > $@

$(MESSAGES):
	make -C ../cbor

$(SUIT_MANIFEST_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/manifest-spec/master/draft-ietf-suit-manifest.cddl -o $@

$(SUIT_TRUST_DOMAINS_CDDL):
	curl https://raw.githubusercontent.com/bremoran/suit-multiple-trust-domains/f/component-id/draft-ietf-suit-trust-domains.cddl -o $@

$(SUIT_REPORT_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/suit-report/main/draft-ietf-suit-report.cddl -o $@

$(COSE_XML):
	curl https://www.ietf.org/archive/id/draft-ietf-cose-msg-24.xml -o $@

$(COSE_CDDL): $(COSE_XML)
	sed -n -e '/<artwork type="CDDL"/,/<\/artwork/ p' $< | sed -e '/<artwork type="CDDL"/ d' -e '/<\/artwork/ d' -e '/<\/section>/,/<figure title=""/ d' -e 's/\&gt;/>/g' -e 's/\r$$//g' > $@

.PHONY: cddl-validate-all
cddl-validate-all: $(CONCATENATED_CDDL) $(TEEP_MESSAGES) $(SUIT_MANIFESTS)
	$(foreach mfst,$(SUIT_MANIFESTS),cddl $(CONCATENATED_UNTAGGED_SUIT_MANIFEST_CDDL) validate $(mfst)
		|| exit 1;)
	$(foreach msg,$(TEEP_MESSAGES),cddl $(CONCATENATED_CDDL) validate $(msg)
		|| exit 1;)

.PHONY: cddl-gen
cddl-gen: cat-cddl $(CONCATENATED_CDDL)
	cddl $(CONCATENATED_CDDL) generate

.PHONY: cddl-validate
cddl-validate: cat-cddl $(MESSAGES) $(CONCATENATED_CDDL)
	cddl $(CONCATENATED_CDDL) validate ../cbor/query_request.diag.bin

.PHONY: clean
clean:
	$(RM) $(CONCATENATED_TEEP_PROTOCOL_CDDL) $(CONCATENATED_SUIT_MANIFEST_CDDL) $(COSE_XML) $(COSE_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(SUIT_REPORT_CDDL)
