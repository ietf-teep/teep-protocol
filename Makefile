FN := $(shell grep 'docname: draft-ietf-teep-protocol' draft-ietf-teep-protocol.md | awk '{print $$2}')

.PHONY: all
all: $(FN).txt $(FN).html

.PHONY: cat-cddl
cat-cddl:
	make -C cddl cat-cddl

.PHONY: validate-cbor
validate-cbor:
	make -C cbor validate

.PHONY: cddl-validate
cddl-validate:
	make -C cddl cddl-validate

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
