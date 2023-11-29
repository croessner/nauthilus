<!-- TOC -->
  * [/etc/systemd/system/nauthilus.service](#etcsystemdsystemnauthilusservice)
  * [/etc/sysconfig/nauthilus](#etcsysconfignauthilus)
<!-- TOC -->

If you prefer installing Nauthilus using a binary, go to the [Download](https://nauthilus.io/downloads/) page and find the
binary for your architecture on Gitlab. Place the file under /usr/local/sbin for example and create a systemd unit file.

## /etc/systemd/system/nauthilus.service

```
[Unit]
Description=Central authentication server
After=network.target nss-lookup.target syslog.target

[Service]
Type=simple
EnvironmentFile=-/etc/sysconfig/nauthilus
ExecStart=/usr/local/sbin/nauthilus
Restart=on-failure
User=nauthilus
Group=nauthilus
[Install]
WantedBy=multi-user.target
```

## /etc/sysconfig/nauthilus

It is recommended to put your configuration settings in a file under /etc/sysconfig/nauthilus (RHEL based systems) or
/etc/default/nauthilus (Debian based systems). For the latter you need to adjust the unit file above to match the given
path.

```
AUTHSERV_VERBOSE_LEVEL="info"
AUTHSERV_HTTP_ADDRESS="[::]:8080"
AUTHSERV_PASSDB_BACKENDS="test"
AUTHSERV_TEST_PASSDB_USERNAME="testuser"
AUTHSERV_TEST_PASSDB_PASSWORD="testpassword"
AUTHSERV_TEST_PASSDB_ACCOUNT="testaccount"
```