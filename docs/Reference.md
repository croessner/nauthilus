<!-- TOC -->
  * [Authserv](#nauthilus)
  * [Nginx](#nginx)
  * [Redis](#redis)
  * [SQL-Backend](#sql-backend)
  * [Test-Backend](#test-backend)
  * [Cache-Backend](#cache-backend)
  * [OAuth2 / Ory Hydra settings](#oauth2--ory-hydra-settings)
    * [Login page (including 2FA page _since_2.1.x_)](#login-page-including-2fa-page-since21x)
    * [Consent page](#consent-page)
    * [Logout page](#logout-page)
    * [2FA specific settings](#2fa-specific-settings)
    * [OAuth2 scopes](#oauth2-scopes)
<!-- TOC -->

This page describes all available environment variables, there meaning and there defaults.

> Note:
>
> All variables are prefixed with AUTHSERV_. For better readability the prefix is left away in this document.

The list of parameters is not following a special order.

> Note 2:
>
> These configuration parameters are not reloaded, if the main process receives a HUP-signal! You must restart the
> service if settings have changed!

## Authserv

| Name    | **DNS_TIMEOUT**          |
|---------|--------------------------|
| Default | 2                        |
| Value   | Positive integer (2-255) |

DNS timeout for the resolver

| Name    | **PASSDB_BACKENDS**                                                                   |
|---------|---------------------------------------------------------------------------------------|
| Default | "cache ldap"                                                                          |
| Values  | * ldap<br/>* mysql<br/>* postgresql<br/>* test<br/>* cache<br/>* proxy _New in 2.1.x_ |

This variable specifies which backends should be used. Backends are processed from left to right and the golden rule is:
first match wins!

| Name    | **FEATURES**                                                                                                                                                                                                                                                                                                                                                                   |
|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Default | "tls_encryption rbl geoip relay_domains"                                                                                                                                                                                                                                                                                                                                       |
| Values  | * tls_encryption: Check, if a remote client used a secured connection to its service<br/>* rbl: Check, if a remote client is known to some RBL list<br/>* geoip: Get some GEO statistics from a remote clients IP address<br/>* relay_domains: Add a static domain list for known supported domains. Unknown requests will be rejected and brute force buckets will be updated |

This parameter controls different aspects of a remote client that must be fulfilled. Geoip itself is currently just for
logging purposes.

| Name    | **BRUTE_FORCE_PROTECTION** |
|---------|----------------------------|
| Default | "http internal-basic-auth" |
| Values  | String                     |

The configuration file may list SQL and/or LDAP search definitions, which list all used protocols used by your
applications. The names are freely choosable. An example of this string may look like: "http imap pop3 sieve submission
smtp ory-hydra".

| Name    | **DEVELOPER_MODE** |
|---------|--------------------|
| Default | False              |
| Value   | Boolean            |

This parameter activates the developer mode. In this mode, redis keys are stored in plain text as well as you can see
passwords in plain text in the logs! Please really use this mode, if you are testing something and have full control
over the system its running on.

| Name    | **INSTANCE_NAME** |
|---------|-------------------|
| Default | nauthilus1         |
| Value   | String            |

This is a unique name for one running instance.

| Name    | **HTTP_ADDRESS** |
|---------|------------------|
| Default | 127.0.0.1:9080   |
| Value   | String           |

This is a IPv4 or IPv6 address followed by ':' and a port number. IPv6 addresses must be enclosed in brackts,
i.e. [::1]. To listen on all interfaces IPv4 and IPv6, specify [::]:9080

| Name    | **HTTP_USE_SSL** |
|---------|------------------|
| Default | False            |
| Value   | Boolean          |

Turn on TLS for the server.

| Name    | **HTTP_TLS_CERT** |
|---------|-------------------|
| Default | -                 |
| Value   | String            |

Define a path to the HTTPS server TLS certificate file containg the certificate and its intermediate certificates (if
any).

| Name    | **HTTP_TLS_KEY** |
|---------|------------------|
| Default | -                |
| Value   | String           |

Define a HTTPS sevrer TLS key file.

| Name    | **HTTP_USE_BASIC_AUTH** |
|---------|-------------------------|
| Default | False                   |
| Value   | Boolean                 |

Turn on HTTP(S) basic authentication for the server.

| Name    | **HTTP_BASIC_AUTH_USERNAME** |
|---------|------------------------------|
| Default | -                            |
| Value   | String                       |

This defines the name for basic authentication.

| Name    | **HTTP_BASIC_AUTH_PASSWORD** |
|---------|------------------------------|
| Default | -                            |
| Value   | String                       |

This defines the password for basic authentication.

| Name    | **RESOLVE_IP** |
|---------|----------------|
| Default | False          |
| Value   | Boolean        |

Authserv can resolve the DNS name for a remote client IP address and log this information.

| Name    | **LOG_FORMAT**       |
|---------|----------------------|
| Default | "default"            |
| Value   | * default<br/>* json |

_Obsolete since 2.2.5_

You can define the log format either being tuples of key=value pairs in a log line or packing it as JSON.

| Name    | **GEOIP_PATH**                        |
|---------|---------------------------------------|
| Default | "/usr/share/GeoIP/GeoLite2-City.mmdb" |
| Value   | String                                |

This is the path to the GEOIP maxmind database file. It can be a city or country databases, Lite or commercial. It is
used with the geoip feature. If you do not use this feature, you do not need to provide a GEOIP database file.

| Name    | **VERBOSE_LEVEL**                                    |
|---------|------------------------------------------------------|
| Default | "none"                                               |
| Value   | * none<br/>* error<br/>* warn<br/>* info<br/>* debug |

Specify the log level. The recommended log level is "info".

| Name    | **TRUSTED_PROXIES** |
|---------|---------------------|
| Default | "127.0.0.1 ::1"     |
| Value   | String              |

If Nauthilus runs behind a reverse proxy or a load balancer, it is necessary to define trusted proxies. This will trust
the X-Forwarded-To header in the HTTP protocol and track the real client IP. This especially needed when using the brute
force protection!

| Name    | **LANGUAGE_RESOURCES** |
|---------|------------------------|
| Default | "/usr/app/resources"   |
| Value   | String                 |

_New since 2.5.0_

Specify the absolute path to the language resources. This directory contains the localized files need for Nauthilus.

## Nginx

| Name    | **NGINX_WAIT_DELAY**     |
|---------|--------------------------|
| Default | 1                        |
| Value   | Positive integer (2-255) |

If a login failed, this value is returned to Nginx to let a client wait. It is a setting for brute force prevention.

| Name    | **NGINX_MAX_LOGIN_ATTEMPTS** |
|---------|------------------------------|
| Default | 15                           |
| Value   | Positive integer (1-255)     |

Replay with Auth-Wait header as long as the maximum login attemtps does not raise the limit of this parameter.

| Name    | **SMTP_BACKEND_ADDRESS** |
|---------|--------------------------|
| Default | "127.0.0.1"              |
| Value   | String                   |

Specify the backend IP address for a SMTP server.

| Name    | **SMTP_BACKEND_PORT**                  |
|---------|----------------------------------------|
| Default | 5871                                   |
| Value   | Positive integer (a valid port number) |

This is the port of a SMTP server.

| Name    | **IMAP_BACKEND_ADDRESS** |
|---------|--------------------------|
| Default | "127.0.0.1"              |
| Value   | String                   |

Specify the backend IP address for a IMAP server.

| Name    | **IMAP_BACKEND_PORT**                  |
|---------|----------------------------------------|
| Default | 9931                                   |
| Value   | Positive integer (a valid port number) |

This is the port of a IMAP server.

## Redis

| Name    | **REDIS_ADDRESS** |
|---------|-------------------|
| Default | "127.0.0.1"       |
| Value   | String            |

Specify the IP address for a Redis server. This server receives write requests.

| Name    | **REDIS_PORT**                         |
|---------|----------------------------------------|
| Default | 6379                                   |
| Value   | Positive integer (a valid port number) |

This is the port of a Redis server.

| Name    | **REDIS_DATABASE_NUMBER** |
|---------|---------------------------|
| Default | 0                         |
| Value   | Positive integer          |

You can speciy the Redis database number that shall be used by nauthilus.

| Name    | **REDIS_USERNAME** |
|---------|--------------------|
| Default | -                  |
| Value   | String             |

If Redis needs authentication, you can specify a username here.

| Name    | **REDIS_PASSWORD** |
|---------|--------------------|
| Default | -                  |
| Value   | String             |

This is the password for a Redis server, if authentication is required.

| Name    | **REDIS_REPLICA_ADDRESS** |
|---------|---------------------------|
| Default | "127.0.0.1"               |
| Value   | String                    |

Specify the IP address for a Redis server. This server receives read requests.

| Name    | **REDIS_REPLICA_PORT**                 |
|---------|----------------------------------------|
| Default | 6379                                   |
| Value   | Positive integer (a valid port number) |

This is the port of a Redis server.

| Name    | **REDIS_PREFIX** |
|---------|------------------|
| Default | "as_"            |
| Value   | String           |

All Redis keys are prefixed.

| Name    | **REDIS_SENTINELS** |
|---------|---------------------|
| Default | -                   |
| Value   | String              |

If you want to use Redis sentinels, you can specify a space separated list of sntinel servers. Each of the form
IP-address:port.

| Name    | **REDIS_SENTINEL_MASTER_NAME** |
|---------|--------------------------------|
| Default | -                              |
| Value   | String                         |

This sets the sentinel master name and is required if using sentinels!

| Name    | **REDIS_SENTINEL_USERNAME** |
|---------|-----------------------------|
| Default | -                           |
| Value   | String                      |

If Redis sentinels need authentication, you can specify a username here.

| Name    | **REDIS_SENTINEL_PASSWORD** |
|---------|-----------------------------|
| Default | -                           |
| Value   | String                      |

This is the password for Redis sentinel servers, if authentication is required.

## SQL-Backend

| Name    | **SQL_MAX_CONNECTIONS** |
|---------|-------------------------|
| Default | 10                      |
| Value   | Positive integer        |

This is the maximum number of SQL connections that can be opened.

| Name    | **SQL_MAX_IDLE_CONNECTIONS** |
|---------|------------------------------|
| Default | 10                           |
| Value   | Integer                      |

This is the maximum number of idle SQL connections.

## Test-Backend

| Name    | **TEST_PASSDB_USERNAME** |
|---------|--------------------------|
| Default | "testpassdbuser"         |
| Value   | String                   |

This is the username of the test backend.

| Name    | **TEST_PASSDB_PASSWORD** |
|---------|--------------------------|
| Default | Random                   |
| Value   | String                   |

If this parameter is not given, a random password is created for the test user. Set a known good password to use this
backend for tests.

| Name    | **TEST_PASSDB_ACCOUNT** |
|---------|-------------------------|
| Default | "testpassdbaccount"     |
| Value   | String                  |

This variable returns a test user account.

## Cache-Backend

| Name    | **REDIS_POSITIVE_CACHE_TTL** |
|---------|------------------------------|
| Default | 3600                         |
| Value   | Positive integer (seconds)   |

This sets the time-to-live parameter for objects in a positive Redis cache which hold user information about the known
passwords. Information on this cache is SHA-256 hashed and 128 bit truncated, if the developer mode is turned off (
default).

| Name    | **REDIS_NEGATIVE_CACHE_TTL** |
|---------|------------------------------|
| Default | 3600                         |
| Value   | Positive integer (seconds)   |

This sets the time-to-live parameter for objects in a negative Redis cache which hold user information about all known
passwords. Information on this cache is SHA-256 hashed and 128 bit truncated, if the developer mode is turned off (
default).

## OAuth2 / Ory Hydra settings


| Name    | **HTTP_STATIC_CONTENT_PATH** |
|---------|------------------------------|
| Default | "/usr/app/static"            |
| Value   | String                       |

_New since 2.0.0_

Define the path where Nauthilus will find OAuth2 pages and content. The default is perfect if using Docker.

| Name    | **DEFAULT_LOGO_IMAGE** |
|---------|------------------------|
| Default | "/static/img/logo.png" |
| Value   | String                 |

Path to the company logo. The path is the location part of a HTTP url.

| Name    | **HYDRA_ADMIN_URI**     |
|---------|-------------------------|
| Default | "http://127.0.0.1:4445" |
| Value   | String                  |

This is the protected URI to the Ory Hydra admin endpoint. You must change this if you plan on using OAuth2!

| Name    | **HTTP_CLIENT_SKIP_TLS_VERIFY** |
|---------|---------------------------------|
| Default | false                           |
| Value   | Boolean                         |

Nauthilus does communicate to Ory Hydra using HTTP. If the server certificate can not be validated, you may turn of
verification

| Name    | **HOMEPAGE**          |
|---------|-----------------------|
| Default | "https://nauthilus.io" |
| Value   | String                |

After a user has logged out, there may exist a user defined post URL. If none was defined, Nauthilus will redirect the
user to this page.

### Login page (including 2FA page _since_2.1.x_)

| Name    | **LOGIN_PAGE** |
|---------|----------------|
| Default | "/login"       |
| Value   | String         |

This is the URI path for the login page. If you change this, you also must modify the page template! Leave it unchanged
if possible!

| Name    | **LOGIN_PAGE_LOGO_IMAGE_ALT**            |
|---------|------------------------------------------|
| Default | "Logo (c) by Roessner-Network-Solutions" |
| Value   | String                                   |

The HTML image alt text for the company logo.

| Name    | **LOGIN_REMEMBER_FOR** |
|---------|------------------------|
| Default | 10800                  |
| Value   | Integer                |

This is the number of seconds a user will not be asked to login again, if the checkbox to remember the user was checked.
This has nothing to do with the calling application, which may keep a user logged in differently. Setting this to 0 (
zero), will keep the user logged in forever. This is not recommended! If you want to disable this feature, you may
consider modifying the page template and removing the checkbox entirely.

| Name    | **LOGIN_PAGE_TITLE** |
|---------|----------------------|
| Default | "Login"              |
| Value   | String               |

_Obsolete since 2.1.x_

The HTML page title tag

| Name    | **LOGIN_PAGE_WELCOME** |
|---------|------------------------|
| Default | -                      |
| Value   | String                 |

If you define this string, a headline will appear on top of the company logo

| Name    | **LOGIN_PAGE_LOGIN** |
|---------|----------------------|
| Default | "Login"              |
| Value   | String               |

_Obsolete since 2.1.x_

This is the labe for the login input field

| Name    | **LOGIN_PAGE_LOGIN_PLACEHOLDER**              |
|---------|-----------------------------------------------|
| Default | "Please enter your username or email address" |
| Value   | String                                        |

_Obsolete since 2.1.x_

This is the help text inside the login input field

| Name    | **LOGIN_PAGE_PASSWORD** |
|---------|-------------------------|
| Default | "Password"              |
| Value   | String                  |

_Obsolete since 2.1.x_

This is the labe for the password input field

| Name    | **LOGIN_PAGE_PASSWORD_PLACEHOLDER** |
|---------|-------------------------------------|
| Default | "Please enter your password"        |
| Value   | String                              |

_Obsolete since 2.1.x_

This is the help text inside the password input field

| Name    | **LOGIN_PAGE_REMEMBER** |
|---------|-------------------------|
| Default | "Remember me"           |
| Value   | String                  |

_Obsolete since 2.1.x_

This is the label for the "remember me" checkbox

| Name    | **LOGIN_PAGE_PRIVACY**                          |
|---------|-------------------------------------------------|
| Default | "We'll never share your data with anyone else." |
| Value   | String                                          |

_Obsolete since 2.1.x_

This text appears under the login field telling the user that his information is processed securely under data
protection aspects

| Name    | **LOGIN_PAGE_SUBMIT** |
|---------|-----------------------|
| Default | "Submit"              |
| Value   | String                |

_Obsolete since 2.1.x_

Text for the submit button

| Name    | **LOGIN_PAGE_POLICY** |
|---------|-----------------------|
| Default | "Privacy policy"      |
| Value   | String                |

_Obsolete since 2.1.x_

If you have created an Ory Hydra client and defined a policy uri, this text will appear as a link under the login form

| Name    | **LOGIN_PAGE_TOS** |
|---------|--------------------|
| Default | "Terms of service" |
| Value   | String             |

_Obsolete since 2.1.x_

If you have created an Ory Hydra client and defined a terms of service uri, this text will appear as a link under the
login form

| Name    | **LOGIN_PAGE_ABOUT**         |
|---------|------------------------------|
| Default | "Get further information..." |
| Value   | String                       |

_Obsolete since 2.1.x_

By creating an Ory Hydra client, you will define a client name. This text will appear as a link under the displayed
application name giving the user the chance to learn more about this application.

### Consent page

| Name    | CONSENT_PAGE |
|---------|--------------|
| Default | "/consent"   |
| Value   | String       |

See LOGIN_PAGE

| Name    | **CONSENT_PAGE_LOGO_IMAGE_ALT**          |
|---------|------------------------------------------|
| Default | "Logo (c) by Roessner-Network-Solutions" |
| Value   | String                                   |

See LOGIN_PAGE_LOGO_IMAGE_ALT

| Name    | **CONSENT_REMEMBER_FOR** |
|---------|--------------------------|
| Default | 3600                     |
| Value   | Integer                  |

See LOGIN_REMEMBER_FOR

| Name    | **CONSENT_PAGE_TITLE** |
|---------|------------------------|
| Default | "Consent"              |
| Value   | String                 |

_Obsolete since 2.1.x_

See LOGIN_PAGE_TITLE

| Name    | **CONSENT_PAGE_WELCOME** |
|---------|--------------------------|
| Default | -                        |
| Value   | String                   |

See LOGIN_PAGE_WELCOME

| Name    | **CONSENT_PAGE_MESSAGE**                      |
|---------|-----------------------------------------------|
| Default | "An application requests access to your data" |
| Value   | String                                        |

_Obsolete since 2.1.x_

See LOGIN_PAGE_MESSAGE

| Name    | **CONSENT_PAGE_REMEMBER** |
|---------|---------------------------|
| Default | "Do not ask me again"     |
| Value   | String                    |

_Obsolete since 2.1.x_

See LOGIN_PAGE_REMEMBER

| Name    | **CONSENT_PAGE_ACCEPT** |
|---------|-------------------------|
| Default | "Accept access"         |
| Value   | String                  |

_Obsolete since 2.1.x_

The text for the accept button

| Name    | **CONSNET_PAGE_REJECT** |
|---------|-------------------------|
| Default | "Deny access"           |
| Value   | String                  |

_Obsolete since 2.1.x_

The text for the reject button

| Name    | **CONSENT_PAGE_POLICY** |
|---------|-------------------------|
| Default | "Privacy policy"        |
| Value   | String                  |

_Obsolete since 2.1.x_

See LOGIN_PAGE_POLICY

| Name    | **CONSENT_PAGE_TOS** |
|---------|----------------------|
| Default | "Terms of service"   |
| Value   | String               |

_Obsolete since 2.1.x_

See LOGIN_PAGE_TOS

| Name    | **CONSENT_PAGE_ABOUT**       |
|---------|------------------------------|
| Default | "Get further information..." |
| Value   | String                       |

_Obsolete since 2.1.x_

See LOGIN_PAGE_ABOUT

### Logout page

| Name    | **LOGOUT_PAGE** |
|---------|-----------------|
| Default | "/logout"       |
| Value   | String          |

See LOGIN_PAGE

| Name    | **LOGOUT_PAGE_TITLE** |
|---------|-----------------------|
| Default | "Logout"              |
| Value   | String                |

_Obsolete since 2.1.x_

See LOGIN_PAGE_TITLE

| Name    | **LOGOUT_PAGE_WELCOME** |
|---------|-------------------------|
| Default | -                       |
| Value   | String                  |

See LOGIN_PAGE_WELCOME

| Name    | **LOGOUT_PAGE_MESSAGE**          |
|---------|----------------------------------|
| Default | "Do you really want to log out?" |
| Value   | String                           |

_Obsolete since 2.1.x_

See LOGIN_PAGE_MESSAGE

| Name    | **LOGOUT_PAGE_ACCEPT** |
|---------|------------------------|
| Default | "Yes"                  |
| Value   | String                 |

_Obsolete since 2.1.x_

See CONSENT_PAGE_ACCEPT

| Name    | **LOGOUT_PAGE_REJECT** |
|---------|------------------------|
| Default | "No"                   |
| Value   | String                 |

_Obsolete since 2.1.x_

### 2FA specific settings

If you provide two factor authentication, the following settings are available:

| Name    | **TOTP_ISSUER** |
|---------|-----------------|
| Default | "nauthilus.me"   |
| Value   | String          |

This field is used in the **otpauth://** URL parameter, when restoring a secret key. It should match the issuer that was
used when creating the key (and read from database afterwards).

> Note:
> 
> The current implementation uses hard-coded settings for TOTP-secrets. These are:
> 
> * algorithm: SHA1
> * Digits: 6

| Name    | **LOGIN_2FA_PAGE** |
|---------|--------------------|
 | Default | "/register"        |
| Value   | String             |

_New since 2.3.x_

This is the URL path where a user can register a second factor for authentication.

> Note:
> 
> The path is relative to /2fa/v1, which is a hardcoded default!

| Name    | **LOGIN_2FA_PAGE_WELCOME** |
|---------|----------------------------|
| Default | -                          |
| Value   | String                     |

_New since 2.3.x_

See LOGIN_PAGE_WELCOME

| Name    | **LOGIN_2FA_POST_PAGE** |
|---------|-------------------------|
| Default | "/totp"                 |
| Value   | String                  |

_New since 2.3.x_

This is the URL path where a user gets redirected to after logging in at the registration endpoint. This may change in
future releases, when webauthn is supported.

> Note:
>
> The path is relative to /2fa/v1, which is a hardcoded default!

| Name    | **TOTP_PAGE** |
|---------|---------------|
| Default | "/totp"       |
| Value   | String        |

_New since 2.3.x_

This is the URL where a user can fetch a QR code of a newly created TOTP code. After the code has been verified by the
user, the code will finally stored in the user backend database.

> Note:
>
> The path is relative to /2fa/v1, which is a hardcoded default!

| Name    | **TOTP_WELCOME** |
|---------|------------------|
| Default | -                |
| Value   | String           |

_New since 2.3.x_

See LOGIN_PAGE_WELCOME

| Name    | **TOTP_PAGE_LOGO_IMAGE_ALT**             |
|---------|------------------------------------------|
| Default | "Logo (c) by Roessner-Network-Solutions" |
| Value   | String                                   |

_Obsolete since 2.1.x_

See LOGIN_PAGE_LOGO_IMAGE_ALT

| Name    | **TOTP_SKEW**    |
|---------|------------------|
| Default | 1                |
| Value   | Positive integer |

_New since 2.4.x_

When using TOTP secrets, this variable is used to allow the server adding **TOTP_SKEW** times 30 seconds periods before 
and after the current time slot. Disable this by setting the variable to 0. Values larger than 1 are sketchy.

| Name    | **NOTIFY_PAGE** |
|---------|-----------------|
| Default | "/notify"       |
| Value   | String          |

_New since 2.3.x_

This is an endpoint for user information returned by Nauthilus.

| Name    | **NOTIFY_WELCOME** |
|---------|--------------------|
| Default | -                  |
| Value   | String             |

_New since 2.3.x_

See LOGIN_PAGE_WELCOME

| Name    | **NOTIFY_PAGE_LOGO_IMAGE_ALT**           |
|---------|------------------------------------------|
| Default | "Logo (c) by Roessner-Network-Solutions" |
| Value   | String                                   |

_Obsolete since 2.1.x_

See LOGIN_PAGE_LOGO_IMAGE_ALT

### OAuth2 scopes

| Name    | **OAUTH2_SCOPE_OPENID**                |
|---------|----------------------------------------|
| Default | "Allow access to identity information" |
| Value   | String                                 |

_Obsolete since 2.1.x_

A descriptive text for the scope openid for the end user

| Name    | **OAUTH2_SCOPE_OFFLINE_ACCESS**                                              |
|---------|------------------------------------------------------------------------------|
| Default | "Allow an application access to private data without your personal presence" |
| Value   | String                                                                       |

_Obsolete since 2.1.x_

A descriptive text for the scope offline_access for the end user

| Name    | **OAUTH2_SCOPE_PROFILE**                |
|---------|-----------------------------------------|
| Default | "Allow access to personal profile data" |
| Value   | String                                  |

_Obsolete since 2.1.x_

A descriptive text for the scope profile for the end user

| Name    | **OAUTH2_SCOPE_EMAIL**               |
|---------|--------------------------------------|
| Default | "Allow access to your email address" |
| Value   | String                               |

_Obsolete since 2.1.x_

A descriptive text for the scope email for the end user

| Name    | **OAUTH2_SCOPE_ADDRESS**            |
|---------|-------------------------------------|
| Default | "Allow access to your home address" |
| Value   | String                              |

_Obsolete since 2.1.x_

A descriptive text for the scope address for the end user

| Name    | **OAUTH2_SCOPE_PHONE**              |
|---------|-------------------------------------|
| Default | "Allow access to your phone number" |
| Value   | String                              |

_Obsolete since 2.1.x_

A descriptive text for the scope phone for the end user

| Name    | **OAUTH2_SCOPE_GROUPS**             |
|---------|-------------------------------------|
| Default | "Allow access to group memberships" |
| Value   | String                              |

_Obsolete since 2.1.x_

A descriptive text for the scope groups for the end user

| Name    | **OAUTH2_SCOPE_OTHER**             |
|---------|------------------------------------|
| Default | "Allow access to a specific scope" |
| Value   | String                             |

_Obsolete since 2.1.x_

A descriptive text for custom defined scopes for the end user, if no explicit description was added inside the
configuration file