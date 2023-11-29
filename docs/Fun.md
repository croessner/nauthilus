If you have a separate log file for nauthilus (i.e. using journald->rsyslog), you can use multitail to watch the logs.

[![img](https://nauthilus.io/wp-content/uploads/2022/11/nauthilus-multitail-1024x679.png)](https://nauthilus.io/wp-content/uploads/2022/11/nauthilus-multitail.png)
multitail -m 0 -cS nauthilus /var/log/mail/nauthilus.log (click to view the picture in full size)

You need to add a color schema to multitail.conf. See the following lines as a good starting point:

```
# nauthilus
colorscheme:nauthilus
cs_re:cyan::
cs_re:red,,bold:.+[eE]rror.+
cs_re:red:.+[wW]arn.+
cs_re:blue|blue,,bold:^... .. ..:..:..
cs_re:red:.+authenticated=fail
cs_re:cyan:authenticated=N/A
cs_re:green:authenticated=ok
cs_re:blue:client_addr=[^ ]+
cs_re:blue:(passdb_backend=|backends=)
cs_re:yellow,,bold:(cachePassDB|ldapPassDB|testPassDB|sqlPassDB)
cs_re:blue:login_attempts=[0-9]+
cs_re:green:failed_passwords_tested=0
cs_re:red:failed_passwords_tested=[0-9]+
cs_re:blue:(http_|tls_)?protocol=
cs_re:blue:tls_cipher=
cs_re:blue:request_method=
cs_re:blue:request_url=
cs_re:yellow,,bold:(imap|smtp|submission|sieve|doveadm)
cs_re:yellow,,bold:HTTP/(1.1|2.0)
cs_re:yellow,,bold:(GET|POST|DELETE)
cs_re:yellow,,bold:request_url=[^ ]*
cs_re:green:(orig_)?username=[^, ]*
cs_re:blue,,bold:.+statistics.+
cs_re:green:security=(TLS|starttls|secured)
cs_re:yellow,,bold:TLS[^ ]*
cs_re:red,,bold:security=[^ ]+
cs_re:green:guid=[^ ]+
cs_re:blue,,bold:level=[^ ]+
cs_re:blue,,bold:caller=[^ ]+
```

Have fun :-)