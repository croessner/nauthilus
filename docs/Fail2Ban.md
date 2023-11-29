<!-- TOC -->
  * [Example log line for RBL](#example-log-line-for-rbl)
  * [Example log line for failed logins](#example-log-line-for-failed-logins)
  * [/etc/fail2ban/filter.d/nauthilus.conf](#etcfail2banfilterdnauthilusconf)
  * [/etc/fail2ban/jail.local](#etcfail2banjaillocal)
<!-- TOC -->

You can easily use fail2ban with nauthilus. This especially interesting, if you use the "rbl" feature.

## Example log line for RBL

```
Feb 13 08:33:39 mx nauthilus[253232]: level=info ts=2023-02-13T08:33:39.847527564+01:00 guid=2Lfskzkuy7jHiCpLV6wlfGxyfq4 rbl="RBL matched" client_addr=XXXXX rbl="AbusiX AuthBL" weight=10
```

## Example log line for failed logins

```
Feb 13 08:33:40 mx nauthilus[253232]: level=info ts=2023-02-13T08:33:40.059720876+01:00 guid=2Lfskzkuy7jHiCpLV6wlfGxyfq4 protocol=submission local_ip=134.255.226.248 port=465 client_addr=XXXXX:60386 client_host=N/A security=TLS auth_method=login username=infiziert@emailforschung.de orig_username=infiziert@emailforschung.de passdb_backend=N/A login_attempts=0 failed_passwords_tested=0 user_agent=Dovecot/2.3 client_id=N/A brute_force_rule=N/A status_message="Invalid login or password" authenticated=fail
```

## /etc/fail2ban/filter.d/nauthilus.conf

```
# Fail2Ban filter for nauthilus
# Detecting unauthorized access to the mail system

[INCLUDES]

# Read common prefixes. If any customizations available -- read them from
# common.local
before = common.conf

[Definition]

mdre-normal = ^%(__prefix_line)slevel=info.+client_addr=<HOST>.+orig_username=<F-USER>.+</F-USER>.+(ua_1d_ipv4|ua_1d_ipv6|b_1min_ipv4_32|b_1min_ipv6_128|b_1h_ipv4_24|b_1h_ipv6_64|b_1d_ipv4_24|b_1d_ipv6_64|b_1w_ipv4_24|b_1w_ipv6_64).+authenticated=fail
mdre-rbl = ^%(__prefix_line)slevel=info.+msg="RBL matched" client_ip=<HOST> rbl_list=.+$

failregex = <mdre-<mode>>

[Init]

journalmatch = CONTAINER_TAG=nauthilus
```

## /etc/fail2ban/jail.local

```ini
#
# nauthilus
#

[nauthilus]
mode     = normal
port     = 143,993,465,587
enabled  = true

[nauthilus-rbl]
filter   = nauthilus[mode=rbl]
port     = 143,993,465,587
maxretry = 1
bantime  = 1d
enabled  = true
```