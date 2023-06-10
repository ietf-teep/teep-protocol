# input files
DIAG_TEEP_MESSAGES := \
		query_request.diag.txt \
		query_response.diag.txt \
		update.diag.txt \
		teep_success.diag.txt \
		teep_error.diag.txt

DIAG_SUIT_MANIFESTS := \
		suit_uri.diag.txt \
		suit_integrated.diag.txt \
		suit_personalization.diag.txt

DIAG_FILES := $(DIAG_TEEP_MESSAGES) $(DIAG_SUIT_MANIFESTS)
HEX_FILES := $(DIAG_TEEP_MESSAGES:.diag.txt=.hex.txt) $(DIAG_SUIT_MANIFESTS:.diag.txt=.hex.txt)

# output files
CBOR_FILES_FROM_DIAG := $(DIAG_FILES:.diag.txt=.diag.bin)
CBOR_FILES_FROM_HEX := $(HEX_FILES:.hex.txt=.hex.bin)

.PHONY: all
all: generate-cbor

.PHONY: generate-cbor
generate-cbor: $(CBOR_FILES_FROM_DIAG) $(CBOR_FILES_FROM_HEX)

%.diag.bin: %.diag.txt
	diag2cbor.rb $< > $@

%.hex.bin: %.hex.txt
	pretty2cbor.rb $< > $@

.PHONY: validate
validate: all
	@echo "Checking each TEEP Protocol DIAG file matches corresponding HEX file"
	$(foreach msg,$(DIAG_TEEP_MESSAGES),diff $(msg:.diag.txt=.diag.bin) $(msg:.diag.txt=.hex.bin) || exit 1;)
	@echo "Checking each SUIT Manifest DIAG file matches corresponding HEX file"
	$(foreach mfst,$(DIAG_SUIT_MANIFESTS),diff $(mfst:.diag.txt=.diag.bin) $(mfst:.diag.txt=.hex.bin) || exit 1;)
	@echo "Success: Each diagnostic notation matches its hex"

.PHONY: clean
clean:
	$(RM) *.bin
