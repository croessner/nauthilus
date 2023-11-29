Here is a sample HAproxy configuration that shows how to put nauthilus behind a load balancer.

> Note:
>
> This is not a complete haproxy.cfg file. Only relevaant snippets are shown here.

```
#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    log         /dev/log local0 info alert
    log         /dev/log local1 notice alert
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon

    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats

    # utilize system-wide crypto-policies
    ssl-default-bind-ciphers PROFILE=SYSTEM
    ssl-default-server-ciphers PROFILE=SYSTEM

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    tcp
    log                     global
    option                  dontlognull
    retries                 3
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout check           10s
    maxconn                 3000
    
userlist basic-auth-list
    user YOUR-USER password $5$....
    
frontend nauthilus
    mode http
    bind ....:443 ssl crt /path/to/crt alpn h2,http/1.1
    acl url_beg path_beg /login /consent /logout /static
    acl invalid_src src 0.0.0.0/7 224.0.0.0/3
    acl invalid_src src_port 0:1023
    tcp-request connection reject if invalid_src
    option tcplog
    use_backend nauthilus_oauth2 if url_beg
    default_backend nauthilus_mail

backend nauthilus_mail
    mode http
    balance leastconn
    acl url_static path /api/v1/http/basicauth
    acl authok http_auth(basic-auth-list)
    http-request auth realm "Protected area" if !url_static !authok
    option tcp-check
    option log-health-checks
    option forwardfor
    server nauthilus1 .... check inter 1m ssl alpn h2 verify none
    server nauthilus2 .... check inter 1m ssl alpn h2 verify none

backend nauthilus_oauth2
    mode http
    balance leastconn
    option tcp-check
    option log-health-checks
    cookie server insert indirect nocache
    option forwardfor
    server nauthilus1 .... cookie p4J1LrlwUm check inter 1m ssl alpn h2 verify none
    server nauthilus2 .... cookie zr4yLa3IT1 check inter 1m ssl alpn h2 verify none
```