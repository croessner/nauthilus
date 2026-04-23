" Vim syntax file
" Language:     Nauthilus configuration (YAML-based)
" Maintainer:   Christian Roessner <christian@roessner.email>
" Comment:      Generated from the config schema; do not edit manually

if exists("b:current_syntax")
  finish
endif

" Case sensitive matching
syntax case match

" Sync from start for consistency
syntax sync fromstart

" --- Level Keywords ---

" L1: Root
syntax match nauthilusKeyL1 /^\zsauth\ze:/
syntax match nauthilusKeyL1 /^\zsidentity\ze:/
syntax match nauthilusKeyL1 /^\zsobservability\ze:/
syntax match nauthilusKeyL1 /^\zsruntime\ze:/
syntax match nauthilusKeyL1 /^\zsstorage\ze:/

" L2: Second level
syntax match nauthilusKeyL2 /^  \zsbackchannel\ze:/
syntax match nauthilusKeyL2 /^  \zsbackends\ze:/
syntax match nauthilusKeyL2 /^  \zsclients\ze:/
syntax match nauthilusKeyL2 /^  \zscontrols\ze:/
syntax match nauthilusKeyL2 /^  \zsfrontend\ze:/
syntax match nauthilusKeyL2 /^  \zshttp\ze:/
syntax match nauthilusKeyL2 /^  \zsinstance_name\ze:/
syntax match nauthilusKeyL2 /^  \zslisten\ze:/
syntax match nauthilusKeyL2 /^  \zslog\ze:/
syntax match nauthilusKeyL2 /^  \zsmetrics\ze:/
syntax match nauthilusKeyL2 /^  \zsmfa\ze:/
syntax match nauthilusKeyL2 /^  \zsoidc\ze:/
syntax match nauthilusKeyL2 /^  \zspipeline\ze:/
syntax match nauthilusKeyL2 /^  \zsprocess\ze:/
syntax match nauthilusKeyL2 /^  \zsprofiles\ze:/
syntax match nauthilusKeyL2 /^  \zsredis\ze:/
syntax match nauthilusKeyL2 /^  \zsrequest\ze:/
syntax match nauthilusKeyL2 /^  \zssaml\ze:/
syntax match nauthilusKeyL2 /^  \zsservices\ze:/
syntax match nauthilusKeyL2 /^  \zssession\ze:/
syntax match nauthilusKeyL2 /^  \zstracing\ze:/
syntax match nauthilusKeyL2 /^  \zsupstreams\ze:/

" L3+: Third level and deeper
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccess_token_claims\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccess_token_lifetime\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccess_token_type\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccount_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaccount_local_cache\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsacs_url\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaction_number_of_workers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsactions\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsactive\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsadaptive_toleration\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsadd_source\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaddress\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsaddresses\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsalgorithm\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsalgorithms\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallow_cleartext_networks\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallow_credentials\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallow_failure\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallow_headers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallow_methods\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallow_origins\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallow_refresh_token_combined_client_auth\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallowed_attributes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsallowlist\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsassets\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsattribute\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_basic\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_header\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_idle_pool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_json\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_jwt\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_method\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_nginx\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_pool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_queue_length\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_rate_limit_burst\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauth_rate_limit_per_second\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauthenticator_attachment\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauthn_requests_signed\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsauto_key_rotation\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsback_channel_enabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsback_channel_max_retries\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsback_channel_session_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsback_channel_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackchannel_logout_uri\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackend\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackend_health_checks\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackend_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackend_number_of_workers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbackend_script_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsban_time\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbase_dn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbasic_auth\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbatching\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbcast\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbind_dn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbind_pw\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbind_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsblock\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbrute_force\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsbuckets\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsburst\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsca_file\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscache_flush_script_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscache_impl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscache_max_entries\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscache_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscb_cooldown\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscb_failure_threshold\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscb_half_open_max\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscert\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscert_file\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zschroot\ze:/
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
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsclients\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscluster\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscode_challenge_methods_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscode_expiry\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscolor\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscompression\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsconfiguration\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsconn_max_idle_time\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsconnect_abort_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsconsent\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsconsent_mode\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsconsent_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscontent_security_policy\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscontent_security_policy_report_only\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscontent_type\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscontent_types\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscontrols\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscors\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscross_origin_embedder_policy\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscross_origin_opener_policy\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscross_origin_resource_policy\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscustom_hooks\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscustom_scopes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zscustom_tolerations\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdatabase_number\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdebug_modules\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdeep_check\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdefault\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdefault_access_token_lifetime\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdefault_expire_time\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdefault_language\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdefault_refresh_token_lifetime\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdelayed_response\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdelimiter\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdescription\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdevice_flow\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdial_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdisabled_endpoints\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdisplay_name_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdn_cache_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdns\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsenable_redis\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsenabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsencryption_secret\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsendpoint\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsentity_id\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsexporter\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsexpose_headers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfailed_requests\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfeature_vm_pool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfilter\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfilter_by_oidc_cid\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfilter_by_protocol\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfilter_vm_pool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfilters\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfrom\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfront_channel_enabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfront_channel_session_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfront_channel_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfrontchannel_logout_session_required\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsfrontchannel_logout_uri\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsgrant_types\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsgroups\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshaproxy_v2\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsheaders\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshealth_check_interval\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshealth_check_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshook_vm_pool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshooks\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshost\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshtml_static_content_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshttp\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshttp3\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshttp_location\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zshttp_method\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsid\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsid_token_claims\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsid_token_signing_alg_values_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsidentity_enabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsidle_connection_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsidle_pool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsimap\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsimplied_scopes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsinclude_raw_result\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsinit_script_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsinit_script_paths\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsip_address\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsip_allowlist\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsip_scoping\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsip_scoping_v4_cidr\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsip_scoping_v6_cidr\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsipv4\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsipv6\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsissuer\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsjson\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zskeep_alive\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zskey\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zskey_file\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zskey_max_age\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zskey_rotation_interval\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslabels\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslanguage_resources\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslanguages\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsldap\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsldap_bind\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsldap_modify\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsldap_search\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslearning\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslevel\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslevel_brotli\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslevel_gzip\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslevel_zstd\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslimit\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslinks\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslist_accounts\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslists\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslocal_cache_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslocal_ip\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslocal_port\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslocalization\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslog_export_results\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslogging\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslogin_attempt\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslogout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslogout_redirect_uri\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslogout_requests_signed\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslogout_responses_signed\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslookup_idle_pool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslookup_pool_only\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslookup_pool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslookup_queue_length\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslua\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslua_backend\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zslua_script\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmaint_notifications_enabled\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmapping\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmappings\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmaster\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmaster_user\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_age\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_batch_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_concurrent_requests\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_connections_per_host\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_depth\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_entries\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_idle_connections\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_idle_connections_per_host\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_items\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_login_attempts\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_participants\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_redirects\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_retries\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_tolerate_percent\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmax_wait\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmembership_cache_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmetrics\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmiddlewares\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmin_length\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmin_tls_version\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmin_tolerate_percent\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmode\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmodify_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsmonitor_connections\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsname\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsname_attribute\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsname_id_format\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsnamed_backends\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsnegative_cache_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsnoloop\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsnumber_of_workers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsoidc_bearer\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsoidc_cid\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsopt_in\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsopt_out\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsoptional_scopes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsorder\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspackage_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspassword\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspassword_encoded\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspassword_forgotten_url\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspassword_history\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspassword_nonce\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspath_prefixes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsper_second\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsperiod\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspermissions_policy\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspipeline_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspolicies\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspolling_interval\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_fifo\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_only\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_size\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspool_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspools\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspop3\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsport\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspositive_cache_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspost_logout_redirect_uris\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspprof\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprefix\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprefixes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprimary\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprivacy_policy_url\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprometheus_timer\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspropagators\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprotocol\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsprotocols\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsproxy\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zspw_history_for_known_accounts\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsqueue_capacity\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsqueue_length\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrate\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrate_limit\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrbl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsread_only\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsread_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrecovery\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrecursive\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsredirect_uris\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsredis_read\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsredis_write\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsreferrer_policy\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrefresh_token_lifetime\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrelay_domains\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsremember_me_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsreplica\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrequest_decompression\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrequest_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrequest_uri\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrequire_mfa\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrequired_scopes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsresident_key\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsresolve_client_ip\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsresolver\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsresponse_compression\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsresponse_types_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsretry_base\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsretry_max\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsretry_max_backoff\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsreturn_code\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsreturn_codes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrevoke_refresh_token\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsroute_by_latency\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsroute_randomly\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsroute_reads_to_replicas\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrp_display_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrp_id\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrp_origins\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrun_as_group\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrun_as_user\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrwp_allowed_unique_hashes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrwp_ipv6_cidr\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsrwp_window\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssampler_ratio\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssasl_external\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsscale_factor\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsscope\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsscopes\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsscopes_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsscript_path\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssearch\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssearch_size_limit\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssearch_time_limit\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssearch_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssecurity_headers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssentinels\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsserver_uri\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsservice_name\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsservice_providers\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsshards\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssignature_method\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssigning_keys\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssingleflight_work\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsskew\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsskip_commands\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsskip_consent\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsskip_verify\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsslo\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsslo_back_channel_url\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsslo_url\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssmtp\ze:/
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
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsstarttls\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsstatic\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsstrategy\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsstrict_transport_security\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssubject_types_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zssupported_mfa\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstargets\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsterms_of_service_url\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstest_password\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstest_username\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsthreshold\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstimeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstimeouts\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls_ca_cert\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls_client_cert\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls_client_key\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls_encryption\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstls_skip_verify\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstoken_endpoint_allow_get\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstoken_endpoint_auth_method\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstoken_endpoint_auth_methods_supported\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstokens\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstolerate_percent\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstolerate_ttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstolerations_ipv6_cidr\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_object_class\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_recovery_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_recovery_object_class\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstotp_secret_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstrusted_proxies\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsttl\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zstype\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsunique_user_id_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsuser\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsuser_code_length\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsuser_verification\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsusername\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswait_delay\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswebauthn\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswebauthn_credential_field\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswebauthn_object_class\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsweight\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswhen_authenticated\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswhen_no_auth\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswhen_unauthenticated\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zswrite_timeout\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsx_content_type_options\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsx_dns_prefetch_control\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsx_frame_options\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsx_permitted_cross_domain_policies\ze:/
syntax match nauthilusKeyL3 /^\(\s\{4,\}\|\s\+-\s\+\)\zsdescription_[A-Za-z0-9_-]\+\ze:/

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
" We use forced colors to ensure they match the requested hierarchy
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
