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
dnf update
dnf install python3-pip git make gem
gem install kramdown-rfc2629
```

Installing required packages on Ubuntu
```
apt-get update
apt-get -y install ruby-kramdown-rfc2629 python3-pip git
pip3 install xml2rfc
git clone https://github.com/ietf-teep/teep-protocol.git
cd teep-protocol/
```

### Generating draft from a markdown file

```
make
```
