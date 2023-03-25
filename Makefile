MD_FILE := draft-ietf-teep-protocol.md
CDDL_FILE := $(MD_FILE:%.md=%.cddl)
FN := $(shell grep 'docname: draft-ietf-teep-protocol' $(MD_FILE) | awk '{print $$2}')

.PHONY: all
all: $(CDDL_FILE) $(FN).txt $(FN).html

.PHONY: cat-cddl
cat-cddl:
	make -C cddl cat-cddl

.PHONY: validate
validate: validate-cbor validate-cddl

.PHONY: validate-cbor
validate-cbor:
	make -C cbor validate

.PHONY: validate-cddl
validate-cddl:
	make -C cddl validate-cddl

.PHONY: validate-teep-cddl
validate-teep-cddl:
	make -C cddl validate-teep-cddl

CODE_PAT	:= ^\~\~\~\~
$(CDDL_FILE): $(MD_FILE)
	> $@
	sed -n '/${CODE_PAT} cddl-teep-message/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' > $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-query-request/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-cipher-suite/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-suit-cose-profile/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-freshness/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-query-response/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-update/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-teep-success/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-teep-error/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-label/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@

$(FN).html: $(FN).xml
	xml2rfc $(FN).xml --html

$(FN).txt: $(FN).xml
	xml2rfc $(FN).xml

$(FN).xml: $(MD_FILE) $(CDDL_FILE)
	kramdown-rfc2629 $(MD_FILE) > $(FN).xml

.PHONY: clean
clean:
	rm -fr $(FN).txt $(FN).xml $(CDDL_FILE)
	$(MAKE) -C cbor clean
	$(MAKE) -C cddl clean
