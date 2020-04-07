IETF_DRAFT_MD = $(wildcard draft-*.md)

IETF_DRAFT = $(patsubst %.md,%, $(IETF_DRAFT_MD))

$(IETF_DRAFT).txt: $(IETF_DRAFT).md
	echo $(IETF_DRAFT)
	kdrfc -3 $<

.PHONY: clean
clean:
	rm -f $(IETF_DRAFT).txt
