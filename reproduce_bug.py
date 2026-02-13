import json

# Mock Data
templates = {
    "CloudFlare": {
        "ipv4": ["1.1.1.0/24"],
        "ipv6": ["2606:4700::/32"]
    }
}

targets = []
selected_keys = ["CloudFlare"]

print("--- Simulating Logic ---")
for key in selected_keys:
    cidrs = templates[key]
    print(f"Type of cidrs: {type(cidrs)}") 
    # The Bug: Iterating dict yields keys
    for c in cidrs: 
        print(f"Adding target: {c}")
        targets.append({'cidr': c, 'prefix': key})

print(f"\nTargets: {targets}")
