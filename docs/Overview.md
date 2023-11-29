# This is the big picture

## Compontents

Nauthilus is part of a number of different services around it. To get an idea, how things work together and want you can
achieve with this software, the following picture is a detailed overview.

```mermaid
flowchart LR
    subgraph Incoming authentication request
        direction LR
        app(((Application))) -->|Alternative 1| ngx[/Nginx with mail plugin/]
        app -->|Alternative 2| dcot[/Dovecot with Lua backend/]
        app -->|Alternative 3| lbr[HAProxy]
        app --- oidc[/OAuth 2 OpenID Connect/]
    end
    subgraph OIDC server
        direction LR
        oidc -->|Frontchannel| ory
        ory <--> lbr
    end
    subgraph Ressources
        direction LR
        as((Nauthilus)) <-->|Backchannel| ory[Ory Hydra]
        as -. uses .-> redis[(Redis DB)]
        as -. uses .-> ldap[(LDAP<br/>Active Directory)]
        as -. uses .-> sql[(SQL DB)]
        as -. uses .-> lua[(Lua backend)]
        as -. may use .-> dns[(DNS Resolver)]
        ngx <-->|Backchannel| as
        dcot <-->|BackChannel| as
        lbr <-->|Backchannel| as
    end
    subgraph Metrics
        prom[Prometheus] -. uses .-> as
    end
```