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
dnf makecache
dnf -y install python3-pip git make gem
gem install kramdown-rfc2629
pip3 install xml2rfc
```

Installing required packages on Ubuntu
```
apt-get update
apt-get -y install ruby-kramdown-rfc2629 python3-pip git
pip3 install xml2rfc
```

Installing cddl tool https://rubygems.org/gems/cddl
```
gem install cddl
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

#### Creating cddl file for TEEP Protocol.

The file name `check-draft-ietf-teep-protocol.cddl` will be created under directory cddl.
The cddl file for TEEP Protocol require cddl file from suit-report and suit-manifest.
This command downloads cddl files from respected repos and concatinate them to one cddl file usable to run with cddl tool.
```
make -C cddl cat-cddl
```

#### Run cddl tools

The command to run cddl syntax check for all teep and suit.
````
make validate-cddl
````

To check syntax cddl syntax in teep file and not suit which is useful during debugging teep by using only QueryRequest which do not contain suit.
```
make -C cddl cddl-validate-teep
```
