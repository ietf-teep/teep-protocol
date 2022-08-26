TXT_MESSAGES := query_request.txt query_response.txt update.txt teep_success.txt teep_error.txt

TXT_CBOR_MESSAGES := $(TXT_MESSAGES:.txt=.tcbor)
HEX_MESSAGES := $(TXT_MESSAGES:.txt=.hex)
HEX_CBOR_MESSAGES := $(TXT_MESSAGES:.txt=.hcbor)

.PHONY: all validate clean

all: $(TXT_CBOR_MESSAGES) $(HEX_CBOR_MESSAGES)

$(TXT_CBOR_MESSAGES): %.tcbor : %.txt
	diag2cbor.rb < $< > $@

$(HEX_CBOR_MESSAGES): %.hcbor : %.hex
	pretty2cbor.rb < $< > $@

validate: all
	$(foreach tmp,$(TXT_MESSAGES),diff $(tmp:.txt=.tcbor) $(tmp:.txt=.hcbor);)

clean:
	$(RM) *.tcbor *.hcbor
