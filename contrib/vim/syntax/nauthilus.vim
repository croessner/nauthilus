" Vim syntax file
" Language:     Nauthilus configuration (YAML-based)
" Maintainer:   Christian Roessner <christian@roessner.email>
" Comment:      Inspired by machine-generated Postfix highlighting

if exists("b:current_syntax")
  finish
endif

" Case sensitive matching
syntax case match

" Sync from start for consistency
syntax sync fromstart

" --- Level Keywords ---

" L1: Root
syntax match nauthilusKeyL1 /^\zsbackend_server_monitoring\ze:/
syntax match nauthilusKeyL1 /^\zsbrute_force\ze:/
syntax match nauthilusKeyL1 /^\zscleartext_networks\ze:/
syntax match nauthilusKeyL1 /^\zsdns\ze:/
syntax match nauthilusKeyL1 /^\zsidp\ze:/
syntax match nauthilusKeyL1 /^\zsinsights\ze:/
syntax match nauthilusKeyL1 /^\zsldap\ze:/
syntax match nauthilusKeyL1 /^\zslog\ze:/
syntax match nauthilusKeyL1 /^\zslua\ze:/
syntax match nauthilusKeyL1 /^\zsmetrics\ze:/
syntax match nauthilusKeyL1 /^\zsoidc\ze:/
syntax match nauthilusKeyL1 /^\zsrealtime_blackhole_lists\ze:/
syntax match nauthilusKeyL1 /^\zsredis\ze:/
syntax match nauthilusKeyL1 /^\zsrelay_domains\ze:/
syntax match nauthilusKeyL1 /^\zssaml2\ze:/
syntax match nauthilusKeyL1 /^\zsserver\ze:/
syntax match nauthilusKeyL1 /^\zstracing\ze:/

" L2: Second level
syntax match nauthilusKeyL2 /^  \zsaction_number_of_workers\ze:/
syntax match nauthilusKeyL2 /^  \zsactions\ze:/
syntax match nauthilusKeyL2 /^  \zsadaptive_toleration\ze:/
syntax match nauthilusKeyL2 /^  \zsaddress\ze:/
syntax match nauthilusKeyL2 /^  \zsauth_idle_pool_size\ze:/
syntax match nauthilusKeyL2 /^  \zsauth_pool_size\ze:/
syntax match nauthilusKeyL2 /^  \zsbackends\ze:/
syntax match nauthilusKeyL2 /^  \zsbasic_auth\ze:/
syntax match nauthilusKeyL2 /^  \zsbrute_force_protocols\ze:/
syntax match nauthilusKeyL2 /^  \zsbuckets\ze:/
syntax match nauthilusKeyL2 /^  \zsclients\ze:/
syntax match nauthilusKeyL2 /^  \zscompression\ze:/
syntax match nauthilusKeyL2 /^  \zsconfig\ze:/
syntax match nauthilusKeyL2 /^  \zsconfiguration\ze:/
syntax match nauthilusKeyL2 /^  \zscustom_hooks\ze:/
syntax match nauthilusKeyL2 /^  \zscustom_scopes\ze:/
syntax match nauthilusKeyL2 /^  \zscustom_tolerations\ze:/
syntax match nauthilusKeyL2 /^  \zsdatabase_number\ze:/
syntax match nauthilusKeyL2 /^  \zsdedup\ze:/
syntax match nauthilusKeyL2 /^  \zsdefault_http_request_header\ze:/
syntax match nauthilusKeyL2 /^  \zsdisabled_endpoints\ze:/
syntax match nauthilusKeyL2 /^  \zsenvironment\ze:/
syntax match nauthilusKeyL2 /^  \zsfeature_vm_pool_size\ze:/
syntax match nauthilusKeyL2 /^  \zsfeatures\ze:/
syntax match nauthilusKeyL2 /^  \zsfilter_vm_pool_size\ze:/
syntax match nauthilusKeyL2 /^  \zsfrontend\ze:/
syntax match nauthilusKeyL2 /^  \zshaproxy_v2\ze:/
syntax match nauthilusKeyL2 /^  \zshook_vm_pool_size\ze:/
syntax match nauthilusKeyL2 /^  \zshttp3\ze:/
syntax match nauthilusKeyL2 /^  \zshttp_client\ze:/
syntax match nauthilusKeyL2 /^  \zsimap_backend_address\ze:/
syntax match nauthilusKeyL2 /^  \zsimap_backend_port\ze:/
syntax match nauthilusKeyL2 /^  \zsinstance_name\ze:/
syntax match nauthilusKeyL2 /^  \zsip_scoping\ze:/
syntax match nauthilusKeyL2 /^  \zsip_whitelist\ze:/
syntax match nauthilusKeyL2 /^  \zsoidc_auth\ze:/
syntax match nauthilusKeyL2 /^  \zskeep_alive\ze:/
syntax match nauthilusKeyL2 /^  \zskey_rotation_interval\ze:/
syntax match nauthilusKeyL2 /^  \zslists\ze:/
syntax match nauthilusKeyL2 /^  \zslocal_cache_auth_ttl\ze:/
syntax match nauthilusKeyL2 /^  \zslookup_idle_pool_size\ze:/
syntax match nauthilusKeyL2 /^  \zslookup_pool_only\ze:/
syntax match nauthilusKeyL2 /^  \zslookup_pool_size\ze:/
syntax match nauthilusKeyL2 /^  \zslua_script_timeout\ze:/
syntax match nauthilusKeyL2 /^  \zsmaster_user\ze:/
syntax match nauthilusKeyL2 /^  \zsmax_concurrent_requests\ze:/
syntax match nauthilusKeyL2 /^  \zsmax_login_attempts\ze:/
syntax match nauthilusKeyL2 /^  \zsmax_password_history_entries\ze:/
syntax match nauthilusKeyL2 /^  \zsmax_tolerate_percent\ze:/
syntax match nauthilusKeyL2 /^  \zsmiddlewares\ze:/
syntax match nauthilusKeyL2 /^  \zsmin_tolerate_percent\ze:/
syntax match nauthilusKeyL2 /^  \zsnginx_wait_delay\ze:/
syntax match nauthilusKeyL2 /^  \zsnumber_of_workers\ze:/
syntax match nauthilusKeyL2 /^  \zspackage_path\ze:/
syntax match nauthilusKeyL2 /^  \zspop3_backend_address\ze:/
syntax match nauthilusKeyL2 /^  \zspop3_backend_port\ze:/
syntax match nauthilusKeyL2 /^  \zsprivacy_policy_url\ze:/
syntax match nauthilusKeyL2 /^  \zsprometheus_timer\ze:/
syntax match nauthilusKeyL2 /^  \zspw_history_for_known_accounts\ze:/
syntax match nauthilusKeyL2 /^  \zsqueue_length\ze:/
syntax match nauthilusKeyL2 /^  \zsrate_limit_burst\ze:/
syntax match nauthilusKeyL2 /^  \zsrate_limit_per_second\ze:/
syntax match nauthilusKeyL2 /^  \zsrwp_allowed_unique_hashes\ze:/
syntax match nauthilusKeyL2 /^  \zsrwp_window\ze:/
syntax match nauthilusKeyL2 /^  \zssasl_external\ze:/
syntax match nauthilusKeyL2 /^  \zsscale_factor\ze:/
syntax match nauthilusKeyL2 /^  \zssearch\ze:/
syntax match nauthilusKeyL2 /^  \zsserver_uri\ze:/
syntax match nauthilusKeyL2 /^  \zsshards\ze:/
syntax match nauthilusKeyL2 /^  \zssigning_keys\ze:/
syntax match nauthilusKeyL2 /^  \zssmtp_backend_address\ze:/
syntax match nauthilusKeyL2 /^  \zssmtp_backend_port\ze:/
syntax match nauthilusKeyL2 /^  \zssoft_whitelist\ze:/
syntax match nauthilusKeyL2 /^  \zsstarttls\ze:/
syntax match nauthilusKeyL2 /^  \zsterms_of_service_url\ze:/
syntax match nauthilusKeyL2 /^  \zsthreshold\ze:/
syntax match nauthilusKeyL2 /^  \zstimeouts\ze:/
syntax match nauthilusKeyL2 /^  \zstls\ze:/
syntax match nauthilusKeyL2 /^  \zstolerate_percent\ze:/
syntax match nauthilusKeyL2 /^  \zstolerate_ttl\ze:/
syntax match nauthilusKeyL2 /^  \zstrusted_proxies\ze:/
syntax match nauthilusKeyL2 /^  \zswebauthn\ze:/

" L3+: Third level and deeper
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccess_token_claims\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccess_token_lifetime\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccess_token_type\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccount_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccount_local_cache\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsacs_url\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsactive\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsadd_source\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaddresses\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsalgorithms\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallow_failure\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallow_mfa_manage\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallowed_attributes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsattribute\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_basic\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_header\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_json\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_jwt\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_method\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_nginx\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_queue_length\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_rate_limit_burst\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_rate_limit_per_second\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_saslauthd\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauto_key_rotation\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsback_channel_logout_session_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsback_channel_logout_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackchannel_logout_uri\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackend_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackend_number_of_workers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackend_script_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackend_servers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbase_dn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbatching\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbcast\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbind_dn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbind_pw\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbind_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbirthdate\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsca_file\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscache_impl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscache_max_entries\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscache_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscb_cooldown\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscb_failure_threshold\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscb_half_open_max\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscert\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscert_file\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscidr\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscipher_suites\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclaim\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclaims\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclaims_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscleanup_interval\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclient_host\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclient_id\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclient_ip\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclient_port\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclient_public_key\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclient_public_key_algorithm\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclient_public_key_file\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclient_secret\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclient_tracking\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscluster\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscolor\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsconn_max_idle_time\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsconnect_abort_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscontent_type\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscontent_types\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdebug_modules\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdeep_check\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdefault_access_token_lifetime\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdefault_expire_time\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdefault_language\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdefault_refresh_token_lifetime\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdelayed_response\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdelimiter\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdescription\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdevice_code_expiry\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdevice_code_polling_interval\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdevice_code_user_code_length\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdial_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdisplay_name_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdistributed_enabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdn_cache_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsemail\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsemail_verified\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsenable_block_profile\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsenable_pprof\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsenable_redis\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsenabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsencryption_secret\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsendpoint\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsentity_id\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsexporter\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfailed_requests\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfamily_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfilter\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfilter_by_oidc_cid\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfilter_by_protocol\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfilters\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfront_channel_logout_session_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfront_channel_logout_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfrontchannel_logout_session_required\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfrontchannel_logout_uri\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsgender\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsgiven_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsgrant_types\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsgroups\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshealth_check_interval\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshealth_check_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshost\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshtml_static_content_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshttp_client_skip_verify\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshttp_location\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshttp_method\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsid\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsid_token_claims\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsid_token_signing_alg_values_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsidentity_enabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsidle_connection_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsidle_pool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsin_process_enabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsinclude_raw_result\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsinit_script_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsinit_script_paths\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsip_address\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsip_scoping_v4_cidr\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsip_scoping_v6_cidr\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsissuer\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsjson\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zskey\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zskey_file\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zskey_max_age\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslabels\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslanguage_resources\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslanguages\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsldap_bind\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsldap_modify\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsldap_search\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslearning\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslevel\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslevel_brotli\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslevel_gzip\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslevel_zstd\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslimit\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslist_accounts\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslocal_ip\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslocal_port\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslocale\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslog_export_results\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslogging\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslogin_attempt\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslogout_redirect_uri\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslookup_queue_length\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslua_backend\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslua_script\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmaint_notifications_enabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmapping\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmappings\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmaster\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_batch_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_connections_per_host\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_idle_connections\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_idle_connections_per_host\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_items\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_redirects\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_retries\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_wait\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmembership_cache_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmiddle_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmin_length\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmin_tls_version\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmodify_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmonitor_connections\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsname\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsname_id_format\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsnegative_cache_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsnickname\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsnoloop\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsoidc_cid\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsopt_in\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsopt_out\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsoptional_ldap_pools\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsoptional_lua_backends\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspassword\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspassword_encoded\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspassword_nonce\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsperiod\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsphone_number\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsphone_number_verified\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspicture\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspipeline_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_fifo\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_only\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsport\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspositive_cache_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspost_logout_redirect_uris\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspreferred_username\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprefix\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprefixes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprofile\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspropagators\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprotocol\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsproxy\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsqueue_capacity\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrate\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrbl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsread_only\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsread_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrecovery\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsredirect_uris\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsredis_read\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsredis_write\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrefresh_token\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrefresh_token_lifetime\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsremember_me_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsreplica\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrequest_decompression\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrequest_uri\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsresolve_client_ip\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsresolver\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsresponse_compression\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsresponse_types_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsretry_base\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsretry_max\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsretry_max_backoff\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsreturn_code\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsreturn_codes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsroute_by_latency\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsroute_randomly\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsroute_reads_to_replicas\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrp_display_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrp_id\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrp_origins\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrwp_ipv6_cidr\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssampler_ratio\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsscope\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsscopes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsscopes_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsscript_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssearch_size_limit\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssearch_time_limit\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssearch_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssentinels\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsservice_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsservice_providers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssignature_method\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssingleflight_work\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsskip_commands\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsskip_consent\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsskip_verify\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsslo_url\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_cipher\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_client_cn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_client_issuer_dn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_client_not_after\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_client_not_before\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_client_subject_dn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_fingerprint\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_issuer\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_issuer_dn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_protocol\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_serial\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_session_id\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_subject\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_subject_dn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsssl_verify\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsstatic\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssubject_types_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstest_password\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstest_username\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstimeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls_ca_cert\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls_client_cert\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls_client_key\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls_skip_verify\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstoken_endpoint_auth_method\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstoken_endpoint_auth_methods_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstolerations_ipv6_cidr\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_issuer\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_object_class\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_recovery_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_recovery_object_class\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_secret_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_skew\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstype\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsunique_user_id_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsupdated_at\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsuser\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsusername\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswebauthn_credential_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswebauthn_object_class\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswebauthn_credentials\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswebsite\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsweight\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswhen_authenticated\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswhen_no_auth\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswhen_unauthenticated\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswrite_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zszoneinfo\ze:/

" --- Special Values ---
syntax keyword nauthilusBoolean true
syntax keyword nauthilusBoolean false
syntax keyword nauthilusBoolean yes
syntax keyword nauthilusBoolean no
syntax keyword nauthilusHttpMethod GET POST PUT DELETE PATCH HEAD OPTIONS CONNECT TRACE

" --- Matches ---
syntax match nauthilusComment "#.*$"
syntax match nauthilusNumber  "\<\d\+\>"
" IPv4 and IPv6 Addresses/Networks, UUIDs and Go Durations
syntax match nauthilusIP "\<\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\%(\/\d\{1,2}\)\?\>"
syntax match nauthilusIP "\<\%([0-9A-Fa-f]\{1,4}:\)\{1,7}\%([0-9A-Fa-f]\{1,4}\|:\)\%(\/\d\{1,3}\)\?\>"
syntax match nauthilusIP "\<\%([0-9A-Fa-f]\{1,4}:\)\{0,6}:[0-9A-Fa-f]\{1,4}\%(\/\d\{1,3}\)\?\>"
syntax match nauthilusIP "\<::\%([0-9A-Fa-f]\{1,4}\)\?\%(\/\d\{1,3}\)\?\>"
syntax match nauthilusUUID "\<[0-9a-fA-F]\{8\}-[0-9a-fA-F]\{4\}-4[0-9a-fA-F]\{3\}-[89abAB][0-9a-fA-F]\{3\}-[0-9a-fA-F]\{12\}\>"
syntax match nauthilusDuration "\<-\?\%(\d\+\%(\.\d\+\)\?\%(ns\|us\|µs\|ms\|s\|m\|h\)\)\+\>"
syntax match nauthilusString  "\".*\"" contains=nauthilusMacro
syntax match nauthilusString  "'.*'" contains=nauthilusMacro
syntax match nauthilusDelimiter ":"

" LDAP Filter highlighting
syntax region nauthilusLdapFilter start="(" end=")" contains=nauthilusLdapFilter,nauthilusLdapOperator,nauthilusMacro
syntax match nauthilusLdapOperator "[&|!<>~=:]" contained

" Macros/Variables
syntax region nauthilusMacro matchgroup=nauthilusMacroDelimiter start="%[LURT]*{" end="}" contains=nauthilusMacroVar oneline
syntax region nauthilusMacro matchgroup=nauthilusMacroDelimiter start="\${" end="}" contains=nauthilusMacroVar oneline
syntax match nauthilusMacroVar /[^}]\+/ contained

" --- Highlighting ---
" We use forced colors to ensure they match the user's request (Dunkelblau, Grün, Gelb)
" but we also link them to standard groups for fallback.

hi def link nauthilusKeyL1 Function
hi def link nauthilusKeyL2 Type
hi def link nauthilusKeyL3 Statement
hi def link nauthilusBoolean Boolean
hi def link nauthilusHttpMethod Special
hi def link nauthilusComment Comment
hi def link nauthilusNumber Number
hi def link nauthilusIP Number
hi def link nauthilusUUID Number
hi def link nauthilusDuration Number
hi def link nauthilusString String
hi def link nauthilusDelimiter Delimiter
hi def link nauthilusLdapFilter Special
hi def link nauthilusLdapOperator Operator
hi def link nauthilusMacro Special
hi def link nauthilusMacroDelimiter Special
hi def link nauthilusMacroVar Special

" Direct color assignments for the requested hierarchy
hi nauthilusKeyL1 ctermfg=4 guifg=#000080 gui=bold
hi nauthilusKeyL2 ctermfg=10 guifg=#00ff00
hi nauthilusKeyL3 ctermfg=11 guifg=#ffff00
hi nauthilusHttpMethod ctermfg=208 guifg=#ff8700 gui=bold
hi nauthilusMacro ctermfg=141 guifg=#af87ff gui=bold
hi nauthilusMacroDelimiter ctermfg=141 guifg=#af87ff gui=bold
hi nauthilusMacroVar ctermfg=141 guifg=#af87ff gui=bold

let b:current_syntax = "nauthilus"
