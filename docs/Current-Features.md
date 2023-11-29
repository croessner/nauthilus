<!-- TOC -->
  * [Database support](#database-support)
  * [Roadmap](#roadmap)
<!-- TOC -->

- Authentication service for Nginx using there HTTP-protocol
- Authentication service for Dovecot using a custom Lua backend
- Authentication service for Cyrus-SASL using the httppost-backend
- Realtime Blackhole lists support
- Using Redis (sentinel) for storing runtime information
- Redis cache backend in front of databases
- TLS support and HTTP basic authorization
- HTTP/2 support
- Metrics support for prometheus. A sample template for grafana is included
- Brute force buckets to detect password attacks
- Static list of known domains. If the login is equal to an email address, Nauthilus can check, if it is responsible for
  this domain
- OAuth2 and OpenID connect support using Ory Hydra. Nauthilus implements the login, consent and logout flows. It ships
  with templates that can be customized to suite your CI/CD.
- Fully optimized LDAP pooling with idle connections
- Basic reloading by reloading the configuration file and restarting database connections
- Dropping all command line parameters
- SQL and LDAP configuration has been moved to the configuration file
- Nauthilus provides custom namespaces for the Redis cache to dynamically deal with different protocol dependent data
- Realtime blackhole lists now have a threshold and each list can have its own weight. Lists are processed in parallel
  and canceled on user defined timeouts
- This version dropped hardcoded protocols. This enables you to nearly add all thinkable services to Nauthilus as long as
  they use the HTTP header protocol described on the start page
- Nauthilus support TOTP two-factor authentication. Therefor it requires a 3rd-party to manage the TOTP secrets. It uses
  a default of 6 digits with SHA1. If you need other options, please open a ticket.
- Nauthilus can be run in proxy-mode. You can delegate requests to a backend server (or more, if you use technics like
  HAProxy or Nginx). The goal is to use caching and features on a frontend system in a firewall DMZ zone, while doing 
  the authentication itself in a security zone, where your databases live.
- Register a user account for TOTP second factor authentication.
- 
## Database support

- OpenLDAP and Active-Directory support
- MySQL and PostgreSQL support
- Proxy-Mode

## Roadmap

- Two-factor authentication – Webauthn
