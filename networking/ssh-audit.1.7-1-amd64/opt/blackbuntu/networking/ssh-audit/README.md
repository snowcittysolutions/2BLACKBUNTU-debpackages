# ssh-audit
[![build status](https://api.travis-ci.org/arthepsy/ssh-audit.svg)](https://travis-ci.org/arthepsy/ssh-audit)
[![coverage status](https://coveralls.io/repos/github/arthepsy/ssh-audit/badge.svg)](https://coveralls.io/github/arthepsy/ssh-audit)  
**ssh-audit** is a tool for ssh server auditing.  

## Features
- SSH1 and SSH2 protocol server support;
- grab banner, recognize device or software and operating system, detect compression;
- gather key-exchange, host-key, encryption and message authentication code algorithms;
- output algorithm information (available since, removed/disabled, unsafe/weak/legacy, etc);
- output algorithm recommendations (append or remove based on recognized software version);
- output security information (related issues, assigned CVE list, etc);
- analyze SSH version compatibility based on algorithm information;
- historical information from OpenSSH, Dropbear SSH and libssh;
- no dependencies, compatible with Python 2.6+, Python 3.x and PyPy;

## Usage
```
usage: ssh-audit.py [-1246pbnvl] <host>

   -1,  --ssh1             force ssh version 1 only
   -2,  --ssh2             force ssh version 2 only
   -4,  --ipv4             enable IPv4 (order of precedence)
   -6,  --ipv6             enable IPv6 (order of precedence)
   -p,  --port=<port>      port to connect
   -b,  --batch            batch output
   -n,  --no-colors        disable colors
   -v,  --verbose          verbose output
   -l,  --level=<level>    minimum output level (info|warn|fail)
   
```
* if both IPv4 and IPv6 are used, order of precedence can be set by using either `-46` or `-64`.  
* batch flag `-b` will output sections without header and without empty lines (implies verbose flag).  
* verbose flag `-v` will prefix each line with section type and algorithm name.  

### example
![screenshot](https://cloud.githubusercontent.com/assets/7356025/19233757/3e09b168-8ef0-11e6-91b4-e880bacd0b8a.png)

## ChangeLog
### v1.7.0 (2016-10-26)
 - implement options to allow specify IPv4/IPv6 usage and order of precedence
 - implement option to specify remote port (old behavior kept for compatibility)
 - add colors support for Microsoft Windows via optional colorama dependency
 - fix encoding and decoding issues, add tests, do not crash on encoding errors
 - use mypy-lang for static type checking and verify all code

### v1.6.0 (2016-10-14)
 - implement algorithm recommendations section (based on recognized software)
 - implement full libssh support (version history, algorithms, security, etc)
 - fix SSH-1.99 banner recognition and version comparison functionality
 - do not output empty algorithms (happens for misconfigured servers)
 - make consistent output for Python 3.x versions
 - add a lot more tests (conf, banner, software, SSH1/SSH2, output, etc)
 - use Travis CI to test for multiple Python versions (2.6-3.5, pypy, pypy3)

### v1.5.0 (2016-09-20)
 - create security section for related security information
 - match and output assigned CVE list and security issues for Dropbear SSH
 - implement full SSH1 support with fingerprint information
 - automatically fallback to SSH1 on protocol mismatch
 - add new options to force SSH1 or SSH2 (both allowed by default)
 - parse banner information and convert it to specific software and OS version
 - do not use padding in batch mode
 - several fixes (Cisco sshd, rare hangs, error handling, etc)

### v1.0.20160902
 - implement batch output option
 - implement minimum output level option
 - fix compatibility with Python 2.6

### v1.0.20160812
 - implement SSH version compatibility feature
 - fix wrong mac algorithm warning
 - fix Dropbear SSH version typo
 - parse pre-banner header
 - better errors handling

### v1.0.20160803
 - use OpenSSH 7.3 banner
 - add new key-exchange algorithms

### v1.0.20160207
 - use OpenSSH 7.2 banner
 - additional warnings for OpenSSH 7.2 
 - fix OpenSSH 7.0 failure messages
 - add rijndael-cbc failure message from OpenSSH 6.7

### v1.0.20160105
 - multiple additional warnings
 - support for none algorithm
 - better compression handling  
 - ensure reading enough data (fixes few Linux SSH)  

### v1.0.20151230
 - Dropbear SSH support  

### v1.0.20151223
 - initial version  
