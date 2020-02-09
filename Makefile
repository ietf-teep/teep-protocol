IETF_DRAFT_XML = $(wildcard *.xml)

IETF_DRAFT = $(patsubst %.xml,%, $(IETF_DRAFT_XML))

$(IETF_DRAFT).txt: %.txt: %.xml
	echo $(IETF_DRAFT)
	xml2rfc $<

#$(IETF_DRAFT).xml: $(IETF_DRAFT).md
#	kramdown-rfc2629 $< > $@

.PHONY: clean
clean:
	rm -f $(IETF_DRAFT).txt
