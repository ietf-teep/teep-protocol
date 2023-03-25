FN := $(shell grep 'docname: draft-ietf-teep-protocol' draft-ietf-teep-protocol.md | awk '{print $$2}')

.PHONY: all
all: $(FN).cddl $(FN).txt $(FN).html

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
%.cddl: %.md
	> $@
	sed -n '/${CODE_PAT} cddl-teep-message/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' > $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-query-request/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-query-response/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-update/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-teep-success/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-teep-error/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-cipher-suite/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@
	sed -n '/${CODE_PAT} cddl-freshness/,/${CODE_PAT}/ p' $< | sed '/${CODE_PAT}.*/ d' >> $@
	echo >> $@

$(FN).html: $(FN).xml
	xml2rfc $(FN).xml --html

$(FN).txt: $(FN).xml
	xml2rfc $(FN).xml

$(FN).xml: draft-ietf-teep-protocol.md
	kramdown-rfc2629 draft-ietf-teep-protocol.md > $(FN).xml

.PHONY: clean
clean:
	rm -fr $(FN).txt $(FN).xml
	$(MAKE) -C cbor clean
	$(MAKE) -C cddl clean
