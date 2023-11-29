<!-- TOC -->
  * [Authserv modes](#nauthilus-modes)
      * [?mode=no-auth](#modeno-auth)
      * [?mode=list-accounts](#modelist-accounts)
<!-- TOC -->

With some Lua glue in Dovecot, it is possible to connect the service directly to nauthilus. Starting with Dovecot 2.319
there exists a HTTP client which can be used to communicate seamlessly with nauthilus.

Here is a real life example on how to achieve this. The mail system is using LDAP. The latter uses a custom schema,
which you can find [here](https://gitlab.roessner-net.de/croessner/openldap-schema/-/tree/main/mail). Upon successful
login, some extra fields are returned for the userdb backend.

Authserv is TLS encrypted and requires HTTP basic authentication. The credentials are read from a file. You can create
one like this:

```shell
echo -n "username:password" | base64 > http-auth.secret
chmod 640 http-auth.secret
chown root:vmail http-auth.secret
```

The Lua code:

```lua
--
-- START settings
--

local http_debug = true;
local http_basicauthfile = "/etc/dovecot/http-auth.secret"
local http_uri = "https://mx.roessner-net.de:9443/api/v1/mail/dovecot"
local http_passwordfail = "Invalid login or password"


--
-- END settings
--


-- HTTP defaults
local http_basicauthpassword
local http_client = dovecot.http.client{
    timeout = 300;
    max_attempts = 3;
    debug = http_debug;
    user_agent = "Dovecot/2.3";
}


local json = require('cjson')


function mysplit(inputstr, sep)
  if sep == nil then
    sep = "%s"
  end
  local t={}
  for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
    table.insert(t, str)
  end
  return t
end


-- Read the http basic auth credentials file
function init_http()
  -- Read nauthilus password
  local file = assert (io.open(http_basicauthfile))
  http_basicauthpassword = file:read("*all")
  file:close()
end


-- Recursive function that can deal with a Dovecot master user
function query_db(request, password, dbtype)
  local remote_ip = request.remote_ip
  local remote_port = request.remote_port
  local local_ip = request.local_ip
  local local_port = request.local_port
  local client_id = request.client_id
  local user_field = ""
  local qs_noauth = ""


  if dbtype == "userdb" then
    qs_noauth = "?mode=no-auth"
  end
  local auth_request = http_client:request {
    url = http_uri .. qs_noauth;
    method = "GET";
  }


  -- Basic Authorization
  auth_request:add_header("Authorization", "Basic " .. http_basicauthpassword)


  if remote_ip == nil then
    remote_ip = "127.0.0.1"
  end
  if remote_port == nil then
    remote_port = "0"
  end
  if local_ip == nil then
    local_ip = "127.0.0.1"
  end
  if local_port == nil then
    local_port = "0"
  end
  if client_id == nil then
    client_id = ""
  end


  -- Do not log internal checks
  if remote_port ~= "0" then
    dovecot.i_info(dbtype .. " service=" .. request.service .. " auth_user=<" .. request.auth_user .. "> user=<" .. request.user .. "> client_addr=" .. remote_ip .. ":" .. remote_port)
  end


  -- Master user: change passdb-query to userdb-query
  if dbtype == "passdb" then
    if request.auth_user:lower() ~= request.user:lower() then
      user_field = "user=" .. request.user
      local userdb_status = query_db(request, "", "userdb")
      if userdb_status == dovecot.auth.USERDB_RESULT_USER_UNKNOWN then
        return dovecot.auth.PASSDB_RESULT_USER_UNKNOWN, ""
      else
        return dovecot.auth.PASSDB_RESULT_OK, user_field
      end
    end
  end


  -- Request
  auth_request:add_header("Auth-Method", request.mech:lower())
  auth_request:add_header("Auth-User", request.user)
  if dbtype == "passdb" then
    auth_request:add_header("Auth-Pass", password)
  end
  auth_request:add_header("Auth-Protocol", request.service)
  auth_request:add_header("Auth-Login-Attempt", "0")
  auth_request:add_header("Client-IP", remote_ip)
  auth_request:add_header("X-Client-Port", remote_port)
  auth_request:add_header("X-Client-Id", client_id)
  auth_request:add_header("X-Local-IP", local_ip)
  auth_request:add_header("X-Auth-Port", local_port)
  if request.secured ~= "" then
    -- Fake SSL certificate
    auth_request:add_header("Auth-SSL", "success")
    auth_request:add_header("Auth-SSL-Protocol", request.secured)
  end


  local auth_response = auth_request:submit()
  local resp_status = auth_response:status()


  -- Response
  local resp_auth_status = auth_response:header("Auth-Status")
  local resp_auth_user = auth_response:header("Auth-User")


  if resp_status == 200 then
    -- Authserv GUID
    local nauthilus_guid = auth_response:header("X-Authserv-Guid")


if guid ~= "" then
  dovecot.i_info(dbtype .. " nauthilus_guid=" .. nauthilus_guid .. " nauthilus_status=\"" .. resp_auth_status .. "\" auth_user=&lt;" .. request.auth_user .. "> user=&lt;" .. request.user .. "> client_addr=" .. remote_ip .. ":" .. remote_port)
end

if resp_auth_user ~= "" then
  user_field = "user=" .. resp_auth_user
else
  return dovecot.auth.USERDB_RESULT_USER_UNKNOWN, ""
end

if resp_auth_status == "OK" then
  local pf = ""
  if dbtype == "passdb" then
    pf = "userdb_"
  end
  local extra_fields = ""

  -- Extra fields
  local quota     = auth_response:header("X-Authserv-Rnsmsquota")
  local quotaof   = auth_response:header("X-Authserv-Rnsmsoverquota")
  local home      = auth_response:header("X-Authserv-Rnsmsmailboxhome")
  local mail      = auth_response:header("X-Authserv-Rnsmsmailpath")
  local fts       = auth_response:header("X-Authserv-Rnsmsdovecotfts")
  local ftssolr   = auth_response:header("X-Authserv-Rnsmsdovecotftssolrurl")
  local aclgroups = auth_response:header("X-Authserv-Rnsmsaclgroups")
  local uid       = auth_response:header("X-Authserv-Uid")

  if quota ~= nil and quota:len()>0 then
    extra_fields = extra_fields .. " " .. pf .. "quota_rule=*:bytes=" .. quota
  end
  if quotaof ~= nil and quotaof:len()>0 then
    extra_fields = extra_fields .. " " .. pf .. "quota_over_flag=" .. quotaof
  end
  if home ~= nil and home:len()>0 then
    extra_fields = extra_fields .. " " .. pf .. "home=" .. home
  end
  if mail ~= nil and mail:len()>0 then
    extra_fields = extra_fields .. " " .. pf .. "mail=" .. mail
  end
  if fts ~= nil and fts:len()>0 then
    extra_fields = extra_fields .. " " .. pf .. "fts=" .. fts
  end
  if ftssolr ~= nil and ftssolr:len()>0 then
    extra_fields = extra_fields .. " " .. pf .. "fts_solr=" .. ftssolr
  end
  if aclgroups ~= nil and aclgroups:len()>0 then
    extra_fields = extra_fields .. " " .. pf .. "acl_groups=" .. aclgroups
  end

  -- extra_fields = extra_fields .. " " .. pf .. "rawlog_dir=/srv/vmail/rawlog/" .. resp_auth_user

  -- Do not log internal checks
  if remote_port ~= "0" then
    dovecot.i_info(dbtype .. " result(" .. uid .. ")=" .. user_field .. extra_fields)
  end
elseif resp_auth_status == http_passwordfail then
  dovecot.i_info(dbtype .. " result=" .. user_field .. " PASSWORD_MISMATCH")
  return dovecot.auth.PASSDB_RESULT_PASSWORD_MISMATCH, ""
end

  end


  dovecot.i_info(dbtype .. " result=" .. user_field .. " INTERNAL_FAILURE")
  if dbtype == "passdb" then
    return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, ""
  else
    return dovecot.auth.USERDB_RESULT_INTERNAL_FAILURE, ""
  end
end


function auth_userdb_lookup(request)
  return query_db(request, "", "userdb")
end


-- {{{
-- This is a dummy function, because Dovecot requires it even it is unused!
-- Create a password: openssl rand -hex 32
function auth_passdb_lookup(request)
  return dovecot.auth.PASSDB_RESULT_OK, "password={PLAIN}bfd988d76f7f9c08aa15060c5fb47179df1c10784bf1d75e2d3a2fcb161e4101"
end
-- }}}


function auth_password_verify(request, password)
  return query_db(request, password, "passdb")
end


function script_init()
  init_http()
  return 0
end


function script_deinit()
end


function auth_userdb_iterate()
  local user_accounts = {}


  local list_request = http_client:request {
    url = http_uri .. "?mode=list-accounts";
    method = "GET";
  }


  -- Basic Authorization
  list_request:add_header("Authorization", "Basic " .. http_basicauthpassword)


  local list_response = list_request:submit()
  local resp_status = list_response:status()


  if resp_status == 200 then
    local payload = list_response:payload()
    user_accounts = mysplit(payload, "\r\n")
  end


  return user_accounts
end
```

Look at the code especially to the response headers. Authserv is delivering all extra fields by prefixing HTTP headers
with X-Authserv- and the name of an extra field.

## Authserv modes

As Dovecot needs three different things like passdb, userdb and iterator, nauthilus was made compatible to deal with
these requirements. By adding a query string to the HTTP request, nauthilus knows what to deliver.

#### ?mode=no-auth

This mode is used for the userdb lookup. It fetches a user and its extra fields. In this mode, no authentication is done
at all.

#### ?mode=list-accounts

This mode returns the full list of known accounts.
