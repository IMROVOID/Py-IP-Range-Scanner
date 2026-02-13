import json

print("\n--- Simulating Fix ---")
templates = {
    "CloudFlare": {
        "ipv4": ["1.1.1.0/24"],
        "ipv6": ["2606:4700::/32"]
    }
}
settings = {"ipv6_enabled": False} # Default

targets = []
selected_keys = ["CloudFlare"]
ipv6_enabled = settings.get('ipv6_enabled', False)

for key in selected_keys:
    tmpl_data = templates[key]
    
    # Handle potential dictionary structure (ipv4/ipv6 keys)
    if isinstance(tmpl_data, dict):
         for ip_type, cidr_list in tmpl_data.items():
              if ip_type == 'ipv6' and not ipv6_enabled: continue
              if isinstance(cidr_list, list):
                   for c in cidr_list: targets.append({'cidr': c, 'prefix': key})
    elif isinstance(tmpl_data, list):
         for c in tmpl_data: targets.append({'cidr': c, 'prefix': key})

print(f"Targets (ipv6_enabled={ipv6_enabled}): {targets}")

# Test with ipv6 enabled
settings["ipv6_enabled"] = True
ipv6_enabled = True
targets_v6 = []
for key in selected_keys:
    tmpl_data = templates[key]
    if isinstance(tmpl_data, dict):
         for ip_type, cidr_list in tmpl_data.items():
              if ip_type == 'ipv6' and not ipv6_enabled: continue
              if isinstance(cidr_list, list):
                   for c in cidr_list: targets_v6.append({'cidr': c, 'prefix': key})

print(f"Targets (ipv6_enabled={ipv6_enabled}): {targets_v6}")
