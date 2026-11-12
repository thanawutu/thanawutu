[settings]
api_mode = v2_policy|v1_site|soar
soar_url = <url>
soar_label = <string>
soar_verify_ssl = <boolean>
soar_ca_file = <path to PEM CA bundle; absolute or relative to the app dir>
soar_proxy = <url>
soar_wait_seconds = <integer>
soar_delete_list_containers = <boolean>
api_v2_base_url = <string>
policy_ids = <comma separated list of Imperva ACL policy IDs>
caid = <integer>
api_base_url = <string>
site_ids = <comma separated list of Imperva site IDs>
max_ips_per_action = <integer>
policy_cache_minutes = <number>
max_cidr_prefix_v4 = <integer>
max_cidr_prefix_v6 = <integer>
protected_networks = <comma separated list of IP/CIDR>
cloud_providers = <regex alternation of AS owner words, e.g. amazon|aws|google>
cloud_check_max_lookups = <integer>
proxy = <url>
verify_ssl = <boolean>
timeout = <integer>

[virustotal]
vt_via = auto|direct|soar
api_base_url = <string>
requests_per_minute = <integer>
max_lookups_per_run = <integer>
rate_limit_retry_seconds = <integer>
rate_limit_max_wait_seconds = <integer>
cache_ttl_hours = <number>
timeout = <integer>
verify_ssl = <boolean>
proxy = <url>
block_malicious = <integer>
review_malicious = <integer>
review_suspicious = <integer>
high_volume_count = <integer>

[auto_unblock]
enabled = on|off
default_days = <integer>
cloud_days = <integer>
scope = all|own
max_per_run = <integer>
start_time = <epoch seconds, empty = when Auto unblock first sees a rule>
