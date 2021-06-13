# Fluentd Twistlock parser

<p>
Use this plugin to Parse Twistlock syslog message into Hashmap. This Make it easy to index in elasticsearch. The Audit Event from twistlock consists of 
helpfull messages that can be used in SIEM. 
</p>

## Feature:
<p>
Parsing of message string into Hashmap and signing with private key. This feature is developed to so that data integrigty can be verified at any given point of time. 
Various compliances like FedRAMP, PCI etc demands for controls where logging data integrity can be checked. 
</p>

## Prerequisite:
```
openssl genrsa -out private.pem 1024
openssl rsa -in private.pem -out public.pem -pubout -outform PEM
```

## Usage:
```
<filter twistsyslog.*.*>
  @type twistlock_syslog
  key_path /fluentd/etc/private.pem
  key_name message
</filter>
```
