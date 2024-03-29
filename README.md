# TEEP Protocol
TEEP Protocol Draft

* [draft-ietf-teep-protocol](./draft-ietf-teep-protocol.md)

## Converting draft

### Prerequisite packages

Requires two packages:
```
kramdown-rfc2629 by Ruby
xml2rfc by Python
```

Installing required packages on Fedora
```
sudo dnf makecache
sudo dnf -y install python3-pip git make gem
gem install kramdown-rfc2629
pip3 install xml2rfc
```

Installing required packages on Ubuntu
```
sudo apt-get update
sudo apt-get -y install python3-pip ruby git curl
pip3 install xml2rfc
gem install kramdown-rfc2629
```

Installing cddl tool https://rubygems.org/gems/cddl
```
gem install cddl
gem update
```

Note that the cddl validation uses this cddl tool, not the one from https://github.com/anweiss/cddl.

### Generating draft from a markdown file

```
git clone https://github.com/ietf-teep/teep-protocol.git
cd teep-protocol/
make
```

It will create `draft-ietf-teep-protocol-latest.txt` and
`draft-ietf-teep-protocol-latest.xml`.

### Checking cddl syntax

#### Creating concatenated cddl file for TEEP Protocol.

The file name 'check-draft-ietf-teep-protocol.cddl' will be created under directory 'cddl'.
The cddl file for TEEP Protocol requires cddl files from suit-report and suit-manifest.
This command downloads cddl files from respected repos and concatenates them to one cddl file usable to run with the cddl tool.
```
make -C cddl
```

#### Perform cddl syntax check with cddl tool.

The command to run FULL cddl syntax check.
````
make validate-cddl
````

To check syntax cddl syntax in TEEP file and not suit which is useful during debugging teep by using only QueryRequest which do not contain SUIT part.
```
make validate-teep-cddl
```

#### Push both md and cddl file to git repo every time revising md file.

The cddl file will be updated from the md file every time when running `make`.

You must push the changes of commit of both md file and cddl file even if you only have changed md file.
