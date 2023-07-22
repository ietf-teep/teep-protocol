TEEP_MESSAGES := \
		../cbor/query_request.diag.bin \
		../cbor/query_response.diag.bin \
		../cbor/update.diag.bin \
		../cbor/teep_success.diag.bin \
		../cbor/teep_error.diag.bin

SUIT_MANIFESTS := \
		../cbor/suit_uri.diag.bin \
		../cbor/suit_integrated.diag.bin \
		../cbor/suit_personalization.diag.bin

CONCATENATED_CDDL		:= check-draft-ietf-teep-protocol.cddl
CONCATENATED_UNTAGGED_SUIT_CDDL	:= check-draft-ietf-suit-manifest.cddl
CONCATENATED_CDDL		:= check-draft-ietf-teep-protocol.cddl
TEEP_PROTOCOL_CDDL		:= ../draft-ietf-teep-protocol.cddl
SUIT_ENVELOPE_SHIM_CDDL := suit-envelope-shim.cddl
SUIT_MANIFEST_CDDL		:= draft-ietf-suit-manifest.cddl
SUIT_TRUST_DOMAINS_CDDL	:= draft-ietf-suit-trust-domains.cddl
SUIT_ENCRYPTED_PAYLOADS_CDDL	:= draft-ietf-suit-firmware-encryption.cddl
SUIT_REPORT_CDDL		:= draft-ietf-suit-report.cddl
SUIT_MTI_CDDL			:= draft-ietf-suit-mti.cddl
COSE_XML			:= rfc-9052-cose.xml
COSE_CDDL			:= rfc-9052-cose.cddl

CDDLS				:= $(TEEP_PROTOCOL_CDDL)
CDDLS				+= $(COSE_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(SUIT_REPORT_CDDL)

.PHONY: cat-cddl
cat-cddl: $(CONCATENATED_CDDL)

$(CONCATENATED_CDDL): $(TEEP_PROTOCOL_CDDL) $(CONCATENATED_UNTAGGED_SUIT_CDDL)
	cat $^ > $@

$(CONCATENATED_UNTAGGED_SUIT_CDDL): $(SUIT_ENVELOPE_SHIM_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(SUIT_REPORT_CDDL) $(SUIT_MTI_CDDL) $(SUIT_ENCRYPTED_PAYLOADS_CDDL) $(COSE_CDDL)
	cat $^ > $@

$(TEEP_MESSAGES) $(SUIT_MANIFESTS):
	make -C ../cbor

$(SUIT_MANIFEST_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/manifest-spec/master/draft-ietf-suit-manifest.cddl -o $@

$(SUIT_TRUST_DOMAINS_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/suit-multiple-trust-domains/main/draft-ietf-suit-trust-domains.cddl -o $@

$(SUIT_REPORT_CDDL):
	curl https://raw.githubusercontent.com/suit-wg/suit-report/main/draft-ietf-suit-report.cddl -o $@

$(SUIT_MTI_CDDL):
	curl https://raw.githubusercontent.com/bremoran/suit-mti/main/draft-ietf-suit-mti.cddl -o $@

$(COSE_XML):
	curl https://www.rfc-editor.org/rfc/rfc9052.xml -o $@

$(COSE_CDDL): $(COSE_XML)
	sed -n -e '/<artwork type="CDDL"/,/<\/artwork/ p' $< | sed -e '/<artwork type="CDDL"/ d' -e '/<\/artwork/ d' -e '/<\/section>/,/<figure title=""/ d' -e 's/\&gt;/>/g' > $@

.PHONY: validate-cddl
validate-cddl: validate-suit-cddl $(CONCATENATED_CDDL) $(TEEP_MESSAGES)
	@echo "Checking each TEEP Protocol binary file matches TEEP Protcol CDDL"
	$(foreach msg,$(TEEP_MESSAGES),cddl $(CONCATENATED_CDDL) validate $(msg) || exit 1;)
	@echo "Success: Each TEEP Protocol message matches the CDDL"

.PHONY: validate-suit-cddl
validate-suit-cddl: $(CONCATENATED_UNTAGGED_SUIT_CDDL) $(SUIT_MANIFESTS)
	@echo "Checking each SUIT Manifest binary file matches SUIT Manifest CDDL"
	$(foreach mfst,$(SUIT_MANIFESTS),cddl $(CONCATENATED_UNTAGGED_SUIT_CDDL) validate $(mfst) || exit 1;)
	@echo "Success: Each SUIT Manifest matches the CDDL"

.PHONY: validate-teep-cddl
validate-teep-cddl: $(CONCATENATED_CDDL) ../cbor/query_request.diag.bin
	cddl $(CONCATENATED_CDDL) validate ../cbor/query_request.diag.bin
	@echo "Success: QueryRequest message matches TEEP Protocol CDDL"

.PHONY: gen-cddl
gen-cddl: cat-cddl $(CONCATENATED_CDDL)
	cddl $(CONCATENATED_CDDL) generate

.PHONY: clean
clean:
	$(RM) $(CONCATENATED_CDDL) $(CONCATENATED_UNTAGGED_SUIT_CDDL) $(COSE_CDDL) $(COSE_XML) $(SUIT_MANIFEST_CDDL) $(SUIT_TRUST_DOMAINS_CDDL) $(SUIT_REPORT_CDDL)
