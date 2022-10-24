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

Installing cddl tool from either https://github.com/anweiss/cddl or
https://rubygems.org/gems/cddl
```
cargo install cddl
```
or
```
gem install cddl
```

### Generating draft from a markdown file

```
git clone https://github.com/ietf-teep/teep-protocol.git
cd teep-protocol/
make
```

It will create `draft-ietf-teep-protocol-latest.txt` and
`draft-ietf-teep-protocol-latest.xml`.
