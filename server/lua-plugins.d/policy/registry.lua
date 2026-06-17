-- Copyright (C) 2026 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.

local AUTHENTICATE = { "authenticate" }

local RESPONSE_MESSAGE_DETAIL = {
    status_message = {
        type = "string",
        sensitivity = "public",
        purpose = "response_message",
        max_length = 256,
    },
}

local function register_attribute(stage, id, value_type, description, details)
    nauthilus_policy.register_attribute({
        id = id,
        stage = stage,
        operations = AUTHENTICATE,
        category = "environment",
        type = value_type,
        description = description,
        details = details,
    })
end

local function pre_auth(id, value_type, description, details)
    register_attribute("pre_auth", id, value_type, description, details)
end

local function subject_analysis(id, value_type, description, details)
    register_attribute("subject_analysis", id, value_type, description, details)
end

pre_auth("lua.plugin.account_longwindow.username", "string", "Account name used by the long-window metric collector.")
pre_auth("lua.plugin.account_longwindow.authenticated", "bool", "Whether the request was authenticated when long-window metrics were collected.")
pre_auth("lua.plugin.account_longwindow.uniq_ips_24h", "number", "Unique account IP estimate over 24 hours.")
pre_auth("lua.plugin.account_longwindow.uniq_ips_7d", "number", "Unique account IP estimate over 7 days.")
pre_auth("lua.plugin.account_longwindow.fails_24h", "number", "Failed account attempts over 24 hours.")
pre_auth("lua.plugin.account_longwindow.fails_7d", "number", "Failed account attempts over 7 days.")
pre_auth("lua.plugin.account_longwindow.has_pw_token", "bool", "Whether the request produced a sprayed-password token.")

pre_auth("lua.plugin.global_pattern.attempts", "number", "Global authentication attempts in the current window.")
pre_auth("lua.plugin.global_pattern.unique_ips", "number", "Global unique IP estimate in the current window.")
pre_auth("lua.plugin.global_pattern.unique_users", "number", "Global unique user estimate in the current window.")
pre_auth("lua.plugin.global_pattern.attempts_per_ip", "number", "Global attempts-per-IP ratio.")
pre_auth("lua.plugin.global_pattern.attempts_per_user", "number", "Global attempts-per-user ratio.")
pre_auth("lua.plugin.global_pattern.ips_per_user", "number", "Global IPs-per-user ratio.")

pre_auth("lua.plugin.security_metrics.global_ips_per_user_24h", "number", "Global IPs-per-user ratio over 24 hours.")
pre_auth("lua.plugin.security_metrics.global_ips_per_user_7d", "number", "Global IPs-per-user ratio over 7 days.")
pre_auth("lua.plugin.security_metrics.protected_accounts", "number", "Number of accounts currently in protection mode.")

pre_auth("lua.plugin.failed_login_hotspot.username", "string", "Username evaluated against the failed-login hotspot set.")
pre_auth("lua.plugin.failed_login_hotspot.count", "number", "Failed-login hotspot score for the account.")
pre_auth("lua.plugin.failed_login_hotspot.rank", "number", "Failed-login hotspot rank for the account.")
pre_auth("lua.plugin.failed_login_hotspot.triggered", "bool", "Whether the account matched the failed-login hotspot threshold.")

pre_auth("lua.plugin.blocklist.matched", "bool", "Whether the remote client matched the blocklist.", RESPONSE_MESSAGE_DETAIL)
pre_auth("lua.plugin.blocklist.client_ip", "ip", "Client IP sent to the blocklist service.")
pre_auth("lua.plugin.blocklist.status_message", "string", "Client-visible blocklist message prepared by the plugin.")

subject_analysis("lua.plugin.account_monitoring.attack_detected", "bool", "Whether account-centric monitoring detected an attack pattern.")
subject_analysis("lua.plugin.account_monitoring.username", "string", "Username evaluated by account-centric monitoring.")
subject_analysis("lua.plugin.account_monitoring.uniq_ips_1h", "number", "Unique account IP estimate over 1 hour.")
subject_analysis("lua.plugin.account_monitoring.uniq_ips_24h", "number", "Unique account IP estimate over 24 hours.")
subject_analysis("lua.plugin.account_monitoring.uniq_ips_7d", "number", "Unique account IP estimate over 7 days.")
subject_analysis("lua.plugin.account_monitoring.failed_24h", "number", "Failed account attempts over 24 hours.")
subject_analysis("lua.plugin.account_monitoring.ratio_24h", "number", "Account IP-to-failure ratio over 24 hours.")

subject_analysis("lua.plugin.account_protection.active", "bool", "Whether account protection mode is active.", RESPONSE_MESSAGE_DETAIL)
subject_analysis("lua.plugin.account_protection.reason", "string", "Comma-separated protection reason codes.")
subject_analysis("lua.plugin.account_protection.backoff_level", "number", "Current account protection backoff level.")
subject_analysis("lua.plugin.account_protection.delay_ms", "number", "Delay applied by account protection mode in milliseconds.")
subject_analysis("lua.plugin.account_protection.enforce_reject", "bool", "Whether account protection mode rejected unauthenticated traffic.")
subject_analysis("lua.plugin.account_protection.status_message", "string", "Client-visible account-protection message prepared by the plugin.")

subject_analysis("lua.plugin.geoip.guid", "string", "GeoIP policy service request identifier.")
subject_analysis("lua.plugin.geoip.current_country_code", "string", "Current ISO-3166 alpha-2 country code from the GeoIP policy service.")
subject_analysis("lua.plugin.geoip.country_codes", "string_list", "Country codes observed by the GeoIP policy service.")
subject_analysis("lua.plugin.geoip.rejected", "bool", "Whether the GeoIP policy service requested rejection.", RESPONSE_MESSAGE_DETAIL)
subject_analysis("lua.plugin.geoip.error", "bool", "Whether the GeoIP policy service returned an error.")
subject_analysis("lua.plugin.geoip.status_message", "string", "Client-visible GeoIP message prepared by the plugin.")

subject_analysis("lua.plugin.geoip_reputation.score", "number", "Weighted signed GeoIP reputation score from Redis.")
subject_analysis("lua.plugin.geoip_reputation.positive_score", "number", "Highest risky GeoIP reputation score across tracked entities.")
subject_analysis("lua.plugin.geoip_reputation.negative_score", "number", "Highest trusted GeoIP reputation score across tracked entities.")
subject_analysis("lua.plugin.geoip_reputation.ip_score", "number", "Signed Redis reputation score for the client IP.")
subject_analysis("lua.plugin.geoip_reputation.asn_score", "number", "Signed Redis reputation score for the client ASN.")
subject_analysis("lua.plugin.geoip_reputation.country_score", "number", "Signed Redis reputation score for the client country.")
subject_analysis("lua.plugin.geoip_reputation.asn_country_score", "number", "Signed Redis reputation score for the ASN country.")
subject_analysis("lua.plugin.geoip_reputation.samples", "number", "Largest sample count among tracked GeoIP reputation entities.")
subject_analysis("lua.plugin.geoip_reputation.decision", "string", "Decision hint derived from GeoIP reputation scores.")

subject_analysis("lua.plugin.idp_policy.rejected", "bool", "Whether the IdP Lua policy rejected the request.", RESPONSE_MESSAGE_DETAIL)
subject_analysis("lua.plugin.idp_policy.reason", "string", "Reason returned by the IdP Lua policy.")
subject_analysis("lua.plugin.idp_policy.oidc_cid", "string", "OIDC client identifier evaluated by the IdP Lua policy.")
subject_analysis("lua.plugin.idp_policy.grant_type", "string", "OIDC grant type evaluated by the IdP Lua policy.")
subject_analysis("lua.plugin.idp_policy.status_message", "string", "Client-visible IdP policy message prepared by the plugin.")

subject_analysis("lua.plugin.director.backend_server", "string", "Backend server selected by the director subject source.")

subject_analysis("lua.plugin.soft_delay.risky", "bool", "Whether the soft-delay subject source considered the request risky.")
subject_analysis("lua.plugin.soft_delay.applied_ms", "number", "Delay applied by the soft-delay subject source in milliseconds.")
