[settings]
api_mode = v2_policy|v1_site
api_v2_base_url = <string>
policy_ids = <comma separated list of Imperva ACL policy IDs>
caid = <integer>
api_base_url = <string>
site_ids = <comma separated list of Imperva site IDs>
max_ips_per_action = <integer>
max_cidr_prefix_v4 = <integer>
max_cidr_prefix_v6 = <integer>
protected_networks = <comma separated list of IP/CIDR>
proxy = <url>
verify_ssl = <boolean>
timeout = <integer>

[virustotal]
api_base_url = <string>
requests_per_minute = <integer>
max_lookups_per_run = <integer>
cache_ttl_hours = <number>
timeout = <integer>
verify_ssl = <boolean>
proxy = <url>
block_malicious = <integer>
review_malicious = <integer>
review_suspicious = <integer>
high_volume_count = <integer>
