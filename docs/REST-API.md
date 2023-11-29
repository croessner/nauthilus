<!-- TOC -->
  * [Backend channel](#backend-channel)
    * [Protocol endpoints](#protocol-endpoints)
    * [REST calls](#rest-calls)
  * [Frontend channel](#frontend-channel)
    * [HTTP basic authorization](#http-basic-authorization-)
    * [OAuth-2.0 OpenID-Connect](#oauth-20-openid-connect)
    * [Manage two-factor authentication requests](#manage-two-factor-authentication-requests)
    * [Other endpoints](#other-endpoints)
  * [Normal user authentication](#normal-user-authentication)
  * [Flush a user from Redis cache](#flush-a-user-from-redis-cache)
  * [Flush an IP address from Redis cache](#flush-an-ip-address-from-redis-cache)
  * [Get a list with all known IP addresses that have been blocked](#get-a-list-with-all-known-ip-addresses-that-have-been-blocked)
  * [Mode no-auth](#mode-no-auth)
  * [Mode list-accounts](#mode-list-accounts)
  * [Nginx](#nginx)
  * [saslauthd with http backend](#saslauthd-with-http-backend)
      * [/etc/saslauthd.conf](#etcsaslauthdconf)
      * [Running saslauthd](#running-saslauthd)
  * [Generic query endpoint _New in version 2.1.x_](#generic-query-endpoint-new-in-version-21x)
<!-- TOC -->

The following is a set of tests which are used for developing. You can use them for your own set of tests.

## Backend channel

**Important!**: Make sure to hide the following endpoints to the public internet:

### Protocol endpoints

* /api/v1/mail/nginx</br>Designed to be used with Nginx
* /api/v1/mail/dovecot</br>Designed to be used with Dovecot compatible servers
* /api/v1/mail/saslauthd</br>Designed to be used with cyrus-saslauthd and its httpform backend.
* /api/v1/generic/user</br>A general purpose endpoint

### REST calls

* /api/v1/cache/flush
* /api/v1/bruteforce/flush

## Frontend channel

### HTTP basic authorization 

**Important!**: Please open this only if you really need it! It lacks the capability for two-factor authentication

* /api/v1/http/basicauth

### OAuth-2.0 OpenID-Connect

The following endpoints may be open for public access:

* /login
* /login/post
* /consent
* /consent/post
* /logout
* /logout/post

### Manage two-factor authentication requests

The following endpoints may be open for public access:

* /2fa/v1/register

### Other endpoints

Nauthilus may call the notification page to display errors or other user information.

* /notify

A query parameter named **message** will be taken from the URL and displayed nicely in a template.

## Normal user authentication

```
GET http://127.0.0.1:8080/api/v1/mail/dovecot
Accept: */*
Auth-Method: plain
Auth-User: testuser
Auth-Pass: testpassword
Auth-Protocol: imap
Auth-Login-Attempt: 0
Client-IP: 127.0.0.1
X-Client-Port: 12345
X-Client-Id: Test-Client
X-Local-IP: 127.0.80.80
X-Auth-Port: 143
Auth-SSL: success
Auth-SSL-Protocol: secured
###
```

Example output:

```
http://127.0.0.1:8080/api/v1/mail/dovecot

HTTP/1.1 200 OK
Auth-Status: OK
Auth-User: testaccount@example.test
X-Authserv-Guid: 2HDQSPruG03RGBCtVuu52ZL18Ip
X-Authserv-Rnsmsdovecotfts: solr
X-Authserv-Rnsmsdovecotftssolrurl: url=http://127.0.0.1:8983/solr/dovecot
X-Authserv-Rnsmsmailpath: sdbox:~/sdbox
X-Authserv-Rnsmsoverquota: FALSE
X-Authserv-Rnsmsquota: 5242880
Date: Mon, 07 Nov 2022 10:32:54 GMT
Content-Length: 2
Content-Type: text/plain; charset=utf-8
OK
```

## Flush a user from Redis cache

```
DELETE http://127.0.0.1:8080/api/v1/cache/flush
Accept: */*
Content-Type: application/json

{"user": "testuser"}
###
```

Example output:

```
HTTP/1.1 200 OK
Content-Type: application/json
Date: Mon, 07 Nov 2022 10:47:31 GMT
Content-Length: 120

{
  "guid": "2HDSEmkavbN4Ih3K89gBBPAGwPy",
  "object": "cache",
  "operation": "flush",
  "result": {
    "user": "testuser",
    "status": "flushed"
  }
}
```

> Note:
>
> If you specify '*' (without the single quotes) as the **user** argument, then all users are flushed from the caches.

## Flush an IP address from Redis cache

```
DELETE http://127.0.0.1:8080/api/v1/bruteforce/flush
Accept: */*
Content-Type: application/json

{"ip_address": "x.x.x.x", "rule_name":  "testrule"}
###
```

Example output:

```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Wed, 22 Mar 2023 12:36:33 GMT
Content-Length: 144

{
  "guid": "2NMzAHKLwpSk6d20cJ4Zqj6hEAB",
  "object": "bruteforce",
  "operation": "flush",
  "result": {
    "ip_address": "x.x.x.x",
    "rule_name": "testrule",
    "status": "flushed"
  }
}
```

> Note:
>
> If you specify '*' (without the single quotes) as the **rule_name** argument, then all buckets an IP belongs to are
> flushed from the caches.

## Get a list with all known IP addresses that have been blocked

```
DELETE http://127.0.0.1:8080/api/v1/bruteforce/list
Accept: */*

###
```

Example output:

```
TTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 27 Mar 2023 09:05:22 GMT
Content-Length: 123

{
  "guid": "2Nah6CvEP1ZK46u6M1GBl8ZuH01",
  "object": "bruteforce",
  "operation": "list",
  "result": {
    "ip_addresses": "ip_addresses": {
      "2a05:bec0:abcd:1::4711": "ua_1d_ipv6"
    },
    "error": "none"
  }
}
```

## Mode no-auth

```
GET http://127.0.0.1:8080/api/v1/mail/dovecot?mode=no-auth
Accept: */*
Auth-Method: plain
Auth-User: testuser
Auth-Protocol: imap
Auth-Login-Attempt: 0
Client-IP: 127.0.0.1
X-Client-Port: 12345
X-Client-Id: Test-Client
X-Local-IP: 127.0.80.80
X-Auth-Port: 143
Auth-SSL: success
Auth-SSL-Protocol: secured
###
```

Example output:

```
HTTP/1.1 200 OK
Auth-Status: OK
Auth-User: testaccount@example.test
X-Authserv-Guid: 2HDSiJqz9MrisZmLAt6iiobOuLQ
X-Authserv-Rnsmsdovecotfts: solr
X-Authserv-Rnsmsdovecotftssolrurl: url=http://127.0.0.1:8983/solr/dovecot
X-Authserv-Rnsmsmailpath: sdbox:~/sdbox
X-Authserv-Rnsmsoverquota: FALSE
X-Authserv-Rnsmsquota: 5242880
Date: Mon, 07 Nov 2022 10:51:26 GMT
Content-Length: 2
Content-Type: text/plain; charset=utf-8

OK
```

## Mode list-accounts

```
GET http://127.0.0.1:8080/api/v1/mail/dovecot?mode=list-accounts
Accept: */*
###
```

The result is a list with all accounts - line by line.

## Nginx

```
GET http://127.0.0.1:8080/api/v1/mail/nginx
Accept: */*
Auth-Method: plain
Auth-User: testuser
Auth-Pass: testpassword
Auth-Protocol: imap
Auth-Login-Attempt: 0
Client-IP: 127.0.0.1
X-Auth-Port: 143
Auth-SSL: success
Auth-SSL-Protocol: secured
###
```

Example output:

```
HTTP/1.1 200 OK
Auth-Port: 9931
Auth-Server: 127.0.0.1
Auth-Status: OK
Auth-User: testaccount@example.test
X-Authserv-Guid: 2HDTGUWG6hNRLfHwafEzDkaZLEC
Date: Mon, 07 Nov 2022 10:55:58 GMT
Content-Length: 2
Content-Type: text/plain; charset=utf-8

OK
```

## saslauthd with http backend

To use this mode, you need to install saslauthd and configure it to use to http backend:

#### /etc/saslauthd.conf

```
httpform_host: 127.0.0.1
httpform_port: 9080
httpform_uri: /api/v1/mail/saslauthd
httpform_data: protocol=submission&port=587&method=plain&tls=success&security=starttls&user_agent=saslauthd/2.1.27&username=%u&realm=%r&password=%p
```

#### Running saslauthd

```
/usr/sbin/saslauthd -m /run/saslauthd -a httpform
```

Using this service prevents nauthilus from finding out the real remote client address. Consider using Dovecot with the
submission proxy service.

```
POST http://127.0.0.1:8080/api/v1/mail/saslauthd
Accept: */*
Content-Type: application/x-www-form-urlencoded

protocol=submission&port=587&method=plain&tls=success&security=starttls&user_agent=Test-Client&username=testuser&realm=&password=testpassword
###
```

Example output:

```
HTTP/1.1 200 OK
Auth-Status: OK
Auth-User: testaccount@example.test
X-Authserv-Guid: 2HDTeoN5dIpcNRvOZt2FNMIrTq3
Date: Mon, 07 Nov 2022 10:59:11 GMT
Content-Length: 2
Content-Type: text/plain; charset=utf-8

OK
```

## Generic query endpoint _New in version 2.1.x_

```
GET http://127.0.0.1:8080/api/v1/generic/user
Accept: */*
Auth-Method: plain
Auth-User: testuser
Auth-Pass: testpassword
Auth-Protocol: generic
Auth-Login-Attempt: 0
Client-IP: 127.0.0.1
X-Auth-Port: 443
Auth-SSL: success
Auth-SSL-Protocol: secured
###
```

Example output:

```
HTTP/1.1 200 OK
Auth-Status: OK
Auth-User: testaccount@example.test
Content-Type: application/json
X-Authserv-Guid: 2MNJnKgGpgGJ5rRuFGcTltWefrO
Date: Tue, 28 Feb 2023 16:37:51 GMT
Content-Length: 656

{
  "AccountField": "entryUUID",
  "TOTPSecretField": "",
  "Password": "***HASHED***",
  "Backend": "ldapPassDB",
  "Attributes": {
    ...
  }
```
