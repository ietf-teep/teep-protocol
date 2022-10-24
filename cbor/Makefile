DIAG_MESSAGES := query_request.diag.txt query_response.diag.txt update.diag.txt teep_success.diag.txt teep_error.diag.txt suit_integrated.diag.txt suit_personalization.diag.txt suit_unlink.diag.txt

DIAG_CBOR_MESSAGES := $(DIAG_MESSAGES:.diag.txt=.diag.bin)
HEX_CBOR_MESSAGES := $(DIAG_MESSAGES:.diag.txt=.hex.bin)

.PHONY: all validate clean

all: $(DIAG_CBOR_MESSAGES) $(HEX_CBOR_MESSAGES)

%.diag.bin: %.diag.txt
	diag2cbor.rb $< > $@

%.hex.bin: %.hex.txt
	pretty2cbor.rb $< > $@

validate: all
	$(foreach msg,$(DIAG_MESSAGES),diff $(msg:.diag.txt=.diag.bin) $(msg:.diag.txt=.hex.bin);)

clean:
	$(RM) *.bin
