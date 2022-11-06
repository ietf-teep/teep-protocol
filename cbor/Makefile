# input files
TEEP_DIAG_MESSAGES := query_request.diag.txt query_response.diag.txt update.diag.txt teep_success.diag.txt teep_error.diag.txt
TEEP_PRETTY_MESSAGES := $(TEEP_DIAG_MESSAGES:.diag.txt=.pretty.txt)
SUIT_DIAG_MESSAGES := suit_uri.diag.txt suit_integrated.diag.txt suit_personalization.diag.txt suit_unlink.diag.txt

HEX_MESSAGES := $(SUIT_DIAG_MESSAGES:.diag.txt=.hex.txt)
DIAG_CBOR_MESSAGES := $(TEEP_DIAG_MESSAGES:.diag.txt=.diag.bin) $(SUIT_DIAG_MESSAGES:.diag.txt=.diag.bin)
PRETTY_CBOR_MESSAGES := $(TEEP_PRETTY_MESSAGES:.pretty.txt=.pretty.bin)

.PHONY: all validate clean

all: $(HEX_MESSAGES) $(DIAG_CBOR_MESSAGES) $(PRETTY_CBOR_MESSAGES)

%.diag.bin: %.diag.txt
	diag2cbor.rb $< > $@

%.pretty.bin: %.pretty.txt
	pretty2cbor.rb $< > $@

%.hex.txt: %.diag.bin
	xxd -p -u $< > $@

validate: all
	$(foreach msg,$(TEEP_DIAG_MESSAGES),diff $(msg:.diag.txt=.diag.bin) $(msg:.diag.txt=.pretty.bin) || echo "msg $(msg) is different";)

clean:
	$(RM) $(HEX_MESSAGES) $(DIAG_CBOR_MESSAGES) $(HEX_CBOR_MESSAGES)
