FN := $(shell grep 'docname: draft-ietf-teep-protocol' draft-ietf-teep-protocol.md | awk '{print $$2}')

.PHONY: all test clean

all: $(FN).txt $(FN).html

test: all
	make -C examples validate

$(FN).html: $(FN).xml
	xml2rfc $(FN).xml --html

$(FN).txt: $(FN).xml
	xml2rfc $(FN).xml

$(FN).xml: draft-ietf-teep-protocol.md
	kramdown-rfc2629 draft-ietf-teep-protocol.md > $(FN).xml

clean:
	rm -fr $(FN).txt $(FN).xml
	$(MAKE) -C examples clean
