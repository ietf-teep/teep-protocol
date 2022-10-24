MESSAGES := ../cbor/query_request.diag.bin ../cbor/query_response.diag.bin ../cbor/update.diag.bin ../cbor/teep_success.diag.bin ../cbor/teep_error.diag.bin

CONCATENATED_CDDL		:= check-draft-ietf-teep-protocol.cddl
TEEP_PROTOCOL_CDDL		:= ../draft-ietf-teep-protocol.cddl
SUIT_MANIFEST_CDDL		:= draft-ietf-suit-manifest.cddl
SUIT_REPORT_MD			:= draft-ietf-suit-report.md
SUIT_REPORT_CDDL		:= draft-ietf-suit-report.cddl
COSE_XML			:= rfc-8152-cose.xml
COSE_CDDL			:= rfc-8152-cose.cddl
WORKAROUND_DEPENDENCY		:= workaround_dependency.cddl

CDDLS				:= $(TEEP_PROTOCOL_CDDL)
CDDLS				+= $(COSE_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_REPORT_CDDL)
CDDLS				+= $(WORKAROUND_DEPENDENCY)

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
	sed -n '/^\~\~\~/,/^\~\~\~/ p' $^ | sed -e '/\~\~\~/ d' -e 's/suit-record-properties     => SUIT_Parameters/suit-record-properties     => \{ \+ SUIT_Parameters \}/g' -e 's/^  \+ SUIT_Param/  * SUIT_Param/' -e 's/SUIT_Parameters/$$$$SUIT_Parameters/g' > $@

$(COSE_XML):
	curl https://www.ietf.org/archive/id/draft-ietf-cose-msg-24.xml -o $@

$(COSE_CDDL): $(COSE_XML)
	sed -n -e '/<artwork type="CDDL"/,/<\/artwork/ p' $^ | sed -e '/<artwork type="CDDL"/ d' -e '/<\/artwork/ d' -e '/<\/section>/,/<figure title=""/ d' -e 's/\&gt;/>/g' > $@

validate: all $(MESSAGES)
	$(foreach msg,$(MESSAGES),cddl $(CONCATENATED_CDDL) validate $(msg) || exit 1;)

clean:
	$(RM) $(CONCATENATED_CDDL) $(COSE_CDDL) $(SUIT_MANIFEST_CDDL) $(SUIT_REPORT_CDDL) $(SUIT_REPORT_MD)
