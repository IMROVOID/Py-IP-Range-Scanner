import os
import sys
import json
import time
import socket
import random
import ipaddress
import requests
import csv
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import msvcrt

# Import utils
try:
    from utils import terminal_file_selector, load_file, clear_screen
except ImportError:
    print("Error: utils.py not found. Please ensure it is in the same directory.")
    sys.exit(1)

# --- Colors ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Constants & Config ---
CONFIG_FILE = os.path.join("Config", "settings.json")
INPUT_DIR = "Input"
TEMP_DIR = "Temp"
OUTPUT_RANGES_DIR = os.path.join("Output", "Ranges")
OUTPUT_FINAL_DIR = os.path.join("Output", "Final")

# Enable VT100 for Windows 10/11 if needed (os.system('color') usually does the trick)
os.system('color')

def print_header(title="IP Range Generator"):
    clear_screen()
    print(f"{Colors.HEADER}={'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{title.center(60)}{Colors.ENDC}")
    print(f"{Colors.HEADER}={'='*60}{Colors.ENDC}")
    print()

class ScanState:
    def __init__(self):
        self.paused = False
        self.stopped = False
        self.save_progress = False

    def toggle_pause(self):
        self.paused = not self.paused
        if self.paused:
            print(f"\n{Colors.WARNING} [PAUSED] Press 'P' to resume...{Colors.ENDC}")
        else:
            print(f"\n{Colors.GREEN} [RESUMED] Continuing scan...{Colors.ENDC}")

    def stop_save(self):
        self.stopped = True
        self.save_progress = True
        print(f"\n{Colors.WARNING} [STOPPING] Saving progress and exiting...{Colors.ENDC}")

    def stop_no_save(self):
        self.stopped = True
        self.save_progress = False
        print(f"\n{Colors.FAIL} [STOPPING] Exiting without saving remaining queue...{Colors.ENDC}")

class ConfigManager:
    def __init__(self):
        self.config = self.load_config()
        
    def load_config(self):
        if not os.path.exists(CONFIG_FILE):
             # Should have been created by setup, but just in case return defaults
             return {"defaults": {}, "templates": {}}
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {"defaults": {}, "templates": {}}

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
            print("Settings saved.")
        except Exception as e:
            print(f"Error saving config: {e}")

    def get_defaults(self):
        return self.config.get('defaults', {})

    def get_templates(self):
        return self.config.get('templates', {})
    
    def update_default(self, key, value):
        self.config.setdefault('defaults', {})[key] = value
        self.save_config()

# --- Logic Classes ---

class IPTester:
    def __init__(self, config_manager):
        self.cfg = config_manager
        self.defaults = self.cfg.get_defaults()
        
    def get_socket_family(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 6:
                return socket.AF_INET6
            return socket.AF_INET
        except ValueError:
            return socket.AF_INET # Default fallback
            
    def test_tcp(self, ip, port, timeout):
        family = self.get_socket_family(ip)
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            start_time = time.time()
            s.connect((ip, port))
            end_time = time.time()
            s.close()
            return int((end_time - start_time) * 1000)
        except:
            return None

    def test_http(self, ip, port, timeout, protocol="http"):
        # Requests handles IPv6 automatically if the URL is formatted correctly.
        # IPv6 literals in URLs must be in brackets: http://[::1]:80
        formatted_ip = f"[{ip}]" if ":" in ip else ip
        url = f"{protocol}://{formatted_ip}:{port}"
        try:
            start_time = time.time()
            requests.get(url, timeout=timeout)
            end_time = time.time()
            return int((end_time - start_time) * 1000)
        except:
            return None
            
    def test_udp(self, ip, port, timeout):
        family = self.get_socket_family(ip)
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            start_time = time.time()
            s.connect((ip, port))
            s.send(b'')
            s.recv(1) # Expect generic response/refusal or timeout
            end_time = time.time()
            s.close()
            return int((end_time - start_time) * 1000)
        except socket.timeout:
            return None
        except:
            return None

    def run_test(self, ip, settings):
        proto = settings.get('protocol', 'tcp').lower()
        port = int(settings.get('port', 443))
        timeout = int(settings.get('timeout', 1000)) / 1000.0
        
        tcp_protos = ['tcp', 'ws', 'grpc', 'httpupgrade', 'splithttp', 'xhttp']
        
        if proto in tcp_protos:
            return self.test_tcp(ip, port, timeout)
        elif proto in ['http', 'https']:
            return self.test_http(ip, port, timeout, proto)
        elif proto in ['udp', 'kcp', 'quic']:
            return self.test_udp(ip, port, timeout)
        return None

    def scan_ips(self, ips, settings, output_dir=OUTPUT_FINAL_DIR):
        """
        Scans a list of IPs with Real-time saving, Pause, and Stop functionality.
        """
        print(f"\n{Colors.HEADER}Starting Scan on {len(ips)} IPs...{Colors.ENDC}")
        print(f"{Colors.CYAN}Controls: [P]ause | [S]top & Save | [Q]uit (No Save){Colors.ENDC}")
        
        max_threads = settings.get('threads', 100)
        output_format = settings.get('output_format', 'txt')  # Force txt/csv for real-time mostly

        # Setup Output File
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"Scan_{ts}.{output_format}"
        filepath = os.path.join(output_dir, filename)
        
        # If resuming (not implemented fully yet, but structure allows it), one would load existing here.
        
        # Initialize State
        state = ScanState()
        
        # Start Input Listener Thread
        def input_listener():
            while not state.stopped:
                if msvcrt.kbhit():
                    try:
                        key = msvcrt.getch().lower()
                        if key == b'p': state.toggle_pause()
                        elif key == b's': state.stop_save()
                        elif key == b'q': state.stop_no_save()
                    except: pass
                time.sleep(0.1)
                
        listener_thread = threading.Thread(target=input_listener, daemon=True)
        listener_thread.start()

        results = []
        # Real-time file handle
        f_handle = open(filepath, 'a', newline='') 
        csv_writer = None
        if output_format == 'csv':
            csv_writer = csv.DictWriter(f_handle, fieldnames=['ip', 'latency_ms', 'status'])
            csv_writer.writeheader()
        elif output_format == 'json':
            # JSON is bad for streaming, we will write a temp list and dump at end, 
            # OR write line-delimited JSON (NDJSON). For compat, let's stick to standard JSON 
            # but we can't write it real-time easily without invalidating syntax.
            # fallback: We will buffer results and write at the very end for JSON, 
            # OR write to a .tmp file and convert. 
            # Let's write text to file line by line as backup, and dump JSON at end?
            # Let's write text to file line by line as backup, and dump JSON at end?
            print(f"{Colors.CYAN} [i] JSON format selected. File will be updated every 100 successful IPs.{Colors.ENDC}")
            f_handle.close() # Close for now
            f_handle = None

        # Thread Pool
        # We need to manage the pool manually to allow pausing.
        # Executors don't pause easily. We will use a Semaphore or simply chunks.
        
        # To support pause/stop effectively with threads, we queue items and threads pick them up.
        # But `map` is blocking. `submit` gives futures.
        
        completed = 0
        success_count = 0
        total = len(ips)
        
        # We'll use a queue or just iterate and submit only when not paused.
        # Actually, simpler: Use Executor but check state inside the task?
        # If paused, task sleeps? No, that blocks threads.
        # Better: The main loop submits tasks. If paused, main loop waits.
        
        # However, checking pause inside task is easier for immediate pause effect, 
        # but holding a thread while paused is bad if we pause for hours (resource usage).
        # For a simple script, sleeping in task is fine.
        
        lock = threading.Lock()
        
        def task(ip):
            # Check pause/stop
            while state.paused:
                time.sleep(0.5)
                if state.stopped: return None
            if state.stopped: return None
            
            ping = self.run_test(ip, settings)
            status = "FAIL"
            if ping is not None and ping <= settings.get('max_ping', 1000):
                status = "SUCCESS"
            
            return {'ip': ip, 'latency_ms': ping if ping is not None else 0, 'status': status}

        futures = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # We submit all? If we submit all, we can't stop submission easily.
            # So we submit in chunks or just handle "stopped" in task (which returns None).
            
            # Submitting 1 million tasks taking memory? Yes.
            # Determine chunk size?
            
            # Let's iterate and submit
            for i, ip in enumerate(ips):
                if state.stopped:
                    break
                    
                while state.paused:
                    time.sleep(0.2)
                    
                # To avoid flooding memory with millions of pending tasks, 
                # we can limit pending tasks? 
                # For now, just submit. Python's overhead for 65k IPs is fine. 
                # For huge lists, we might want to check queue size, but let's keep it simple.
                future = executor.submit(task, ip)
                futures.append(future)
                
                # Check status periodically
                # (This loop runs fast, so we mostly just fill the queue)
                # To make the loop responsive to 'Pause' blocking submission:
                # The 'while state.paused' above handles it.
                
            # Process results as they complete
            # We want to write results AS they finish.
            # `as_completed` is good for this.
            
            from concurrent.futures import as_completed
            
            for future in as_completed(futures):
                # If we stopped, we might still have pending tasks completing.
                # We can ignore them or process them. 
                # If "Stop & Save", we process what we have.
                res = future.result()
                if not res: continue # Was stopped/cancelled
                
                with lock:
                    completed += 1
                    if res['status'] == 'SUCCESS':
                        success_count += 1
                        
                    # UI Update
                    sys.stdout.write(f"\r[{completed}/{total}] {Colors.BLUE}Scanning...{Colors.ENDC} {Colors.GREEN}Success: {success_count}{Colors.ENDC}")
                    sys.stdout.flush()
                    
                    # Save Real-time
                    if res['status'] == 'SUCCESS' or settings.get('save_failed', False):
                        if f_handle:
                            if output_format == 'csv':
                                csv_writer.writerow(res)
                            elif output_format == 'txt':
                                f_handle.write(f"{res['ip']} | {res['latency_ms']}ms | {res['status']}\n")
                            f_handle.flush() # Ensure it hits disk
                        if output_format == 'json':
                            results.append(res)
                            # Periodic JSON Save (Every 100 successes or so)
                            if len(results) % 100 == 0:
                                # Write to a temp file then rename? Or just overwrite.
                                # Overwriting is safer than appending to JSON.
                                try:
                                    out = {"settings": settings, "results": results}
                                    with open(filepath, 'w') as f:
                                        json.dump(out, f, indent=2)
                                except: pass

        print(f"\n{Colors.BOLD}Scan Finished or Stopped.{Colors.ENDC}")
        if f_handle:
            f_handle.close()
            
        # Final JSON dump if needed (To ensure everything is saved)
        if output_format == 'json' and results:
            print("Saving Final JSON report...")
            out = {"settings": settings, "results": results}
            with open(filepath, 'w') as f: # Overwrite/Create
                json.dump(out, f, indent=2)
                
        print(f"{Colors.GREEN}Results saved to: {filepath}{Colors.ENDC}")

class IPGenerator:
    def __init__(self, tester):
        self.tester = tester
        
    def expand_cidr(self, cidr):
        try:
            return [str(ip) for ip in ipaddress.ip_network(cidr.strip(), strict=False)]
        except:
            return []
            
    def get_sample_ip(self, cidr):
        """Returns a random/sample IP from the CIDR for pre-scan."""
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            
            # Helper for IPv6 big networks logic or IPv4
            # If network is huge (IPv6 /32 is insanely huge), we can't iterate.
            # We must construct a random address inside.
            
            if net.version == 6:
                # Generate random host part
                # network_address + random(0, num_addresses - 1)
                # But num_addresses is too big for float/int sometimes in simple math? Python handles large ints fine.
                # Just take a random int between 1 and min(1000, max_hosts) to stay "close" to start?
                # Or truly random?
                # Usually we want to test if the routing to that prefix works.
                # Let's pick a random one in the first few subnets or completely random.
                
                # Simple approach: net[1] (gatewayish) or random
                # Taking net[1] is safest for availability checks often.
                return str(net[1]) 
            else:
                # IPv4
                if net.num_addresses > 2:
                    idx = random.randint(1, min(net.num_addresses - 2, 100)) 
                    return str(net[idx])
                else:
                    return str(net[0])
        except:
            return None

    def generate_and_save(self, cidrs, output_dir=OUTPUT_RANGES_DIR):
        """
        Generates lists of IPs from CIDRs and saves them.
        Returns list of generated file paths.
        """
        generated_files = []
        
        # Ensure dir exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        for cidr in cidrs:
            print(f"Generating IPs for {Colors.BOLD}{cidr}{Colors.ENDC}...")
            
            # WARNING: IPv6 /32 expansion is impossible (billions of IPs).
            # We must check size before exploding.
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
                if net.version == 6:
                    print(f" [!] Skipping full expansion for IPv6 range {cidr} (Too large).")
                    print(f"     Generate a limited sample? Or skip?")
                    # Users usually don't want a text file with 2^96 IPs.
                    # We'll skip saving a file for IPv6 ranges or limit it.
                    # Let's generate a small sample (e.g. 1000 IPs) for testing?
                    # Or just notify.
                    print(f"     {Colors.WARNING}IPv6 expansion is disabled to prevent disk overflow.{Colors.ENDC}")
                    continue
            except:
                pass

            ips = self.expand_cidr(cidr)
            if not ips: 
                print(f"Invalid CIDR: {cidr}")
                continue
            
            # Double check size for IPv4 too (e.g. /8)
            if len(ips) > 1000000:
                print(f" [!] Range {cidr} has {len(ips)} IPs. This will be a large file.")

            filename = f"Range_{cidr.replace('/', '_').replace(':', '')}.txt"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'w') as f:
                for ip in ips:
                    f.write(ip + '\n')
            
            print(f" -> Saved {len(ips)} IPs to {filename}")
            generated_files.append(filepath)
            
        return generated_files

    def pre_scan_templates(self, templates_dict, settings):
        # This method is not directly used in the new flow (logic moved to menu), 
        # but if we wanted to keep it generic:
        pass

# --- Menu & Main ---

def get_user_settings_override(defaults):
    """Simple prompt to override basic settings for a run."""
    print_header("Scan Settings")
    print(f"{Colors.HEADER}Current Settings:{Colors.ENDC}")
    for k, v in defaults.items():
        print(f"  {k:<15}: {v}")
    print()
    
    if input("Change settings for this run? (y/N): ").lower() != 'y':
        return defaults.copy()
        
    new_settings = defaults.copy()
    try:
        p = input(f"Port ({defaults.get('port', 443)}): ")
        if p: new_settings['port'] = int(p)
        
        prot = input(f"Protocol ({defaults.get('protocol', 'tcp')}): ")
        if prot: new_settings['protocol'] = prot
        
        to = input(f"Timeout ({defaults.get('timeout', 1000)}): ")
        if to: new_settings['timeout'] = int(to)
        
        fmt = input(f"Output Format ({defaults.get('output_format', 'json')}): ")
        if fmt: new_settings['output_format'] = fmt
        
    except Exception as e:
        print(f"Invalid input, using defaults. Error: {e}")
        
    return new_settings

def menu_scan_ip_ranges(cfg, tester, generator):
    print_header("Scan IP Ranges")
    
    # 1. Select Source
    print(f"{Colors.BOLD}Select Source:{Colors.ENDC}")
    print("  1. Use Templates (CloudFlare/Fastly)")
    print("  2. Select File with Ranges")
    print("  3. Back")
    src = input("\nSelect (1-3): ").strip()
    
    if src == '3': return
    
    cidrs_to_scan = [] # List of CIDR strings
    
    if src == '1':
        templates = cfg.get_templates()
        providers = list(templates.keys())
        print(f"\n{Colors.CYAN}Available Providers:{Colors.ENDC}")
        for i, p in enumerate(providers):
            print(f"  {i+1}. {p}")
        print(f"  {len(providers)+1}. All")
        
        selected_providers = []
        try:
            sel = int(input("Select: "))
            if 0 < sel <= len(providers):
                selected_providers = [providers[sel-1]]
            else:
                selected_providers = providers
        except:
             selected_providers = providers
        
        # Ask for IPv6
        defaults = cfg.get_defaults()
        use_ipv6 = defaults.get('ipv6_enabled', False)
        
        print(f"\nIPv6 is currently {'ENABLED' if use_ipv6 else 'DISABLED'} by default.")
        override_ipv6 = input("Include IPv6 ranges? (y/n/default): ").strip().lower()
        if override_ipv6 == 'y': use_ipv6 = True
        elif override_ipv6 == 'n': use_ipv6 = False
        
        for p in selected_providers:
            p_data = templates[p]
            # Handle new structure (dict with ipv4/ipv6 keys) vs old list
            if isinstance(p_data, dict):
                if 'ipv4' in p_data:
                    cidrs_to_scan.extend(p_data['ipv4'])
                if use_ipv6 and 'ipv6' in p_data:
                    cidrs_to_scan.extend(p_data['ipv6'])
            elif isinstance(p_data, list):
                # Fallback for old style (assumed IPv4)
                cidrs_to_scan.extend(p_data)

    elif src == '2':
        # File selector
        files = terminal_file_selector(INPUT_DIR, extensions=['.txt', '.json', '.csv'])
        for f in files:
            data = load_file(f)
            for d in data:
                if 'ip' in d: cidrs_to_scan.append(d['ip'])
    
    if not cidrs_to_scan:
        print("No ranges selected.")
        return

    # User settings for the scan
    settings = get_user_settings_override(cfg.get_defaults())

    # 2. Stage 1: Pre-Scan
    print(f"\nPhase 1: Pre-Scanning {len(cidrs_to_scan)} Ranges...")
    
    successful_cidrs = []
    print("Sampling ranges to check generic availability...")
    for cidr in cidrs_to_scan:
        sample = generator.get_sample_ip(cidr)
        if not sample: continue
        res = tester.run_test(sample, settings)
        if res:
            print(f"   [{Colors.GREEN}+{Colors.ENDC}] {cidr} seems UP ({res}ms)")
            successful_cidrs.append(cidr)
        else:
            print(f"   [{Colors.FAIL}-{Colors.ENDC}] {cidr} seems DOWN (Sample {sample} failed)")
            
    if not successful_cidrs:
        print("No working ranges found.")
        return

    # 3. Method 2 logic: Generate Files
    print(f"\nPhase 2: Generating Files for {len(successful_cidrs)} ranges...")
    generated_files = generator.generate_and_save(successful_cidrs)
    
    if not generated_files:
        print("No files generated (IPv6 ranges are skipped for full generation to avoid huge files).")
        # For IPv6, we might just want to Skip "Scan Each IP" or handle it differently?
        # If user wants to scan IPv6, they typically scan specific IPs or small ranges. 
        # Scanning a /32 is impossible.
    
    # 4. Ask to Scan Each IP (Only if we have files)
    if generated_files:
        if input("\nDo you want to scan EACH IP in these ranges? (y/N): ").lower() == 'y':
            all_ips = []
            for gf in generated_files:
                try:
                    with open(gf, 'r') as f:
                        all_ips.extend([line.strip() for line in f if line.strip()])
                except: pass
                
            tester.scan_ips(all_ips, settings)

def menu_scan_ips(cfg, tester):
    print_header("Scan IPs (Direct)")
    print("  1. Terminal Input")
    print("  2. File Input")
    print("  3. Back")
    src = input("\nSelect (1-3): ").strip()
    
    if src == '3': return
    
    ips_to_scan = []
    
    if src == '1':
        inp = input("Enter IP (or comma separated): ")
        ips_to_scan = [i.strip() for i in inp.split(',') if i.strip()]
    elif src == '2':
        files = terminal_file_selector(INPUT_DIR)
        for f in files:
            data = load_file(f) # Returns list of dicts
            for d in data:
                if 'ip' in d: ips_to_scan.append(d['ip'])
                
    if not ips_to_scan:
        print("No IPs.")
        return
        
    settings = get_user_settings_override(cfg.get_defaults())
    tester.scan_ips(ips_to_scan, settings)

def menu_settings(cfg):
    while True:
        print_header("Global Settings")
        defaults = cfg.get_defaults()
        print(f"{Colors.BOLD}{'Key':<20} {'Value':<20}{Colors.ENDC}")
        print("-" * 40)
        for k, v in defaults.items():
            print(f"{k:<20} {v}")
            
        print(f"\n{Colors.CYAN}Commands:{Colors.ENDC}")
        print("  edit <key> <val>   (e.g., edit threads 200)")
        print("  back               (Return to Main Menu)")
        
        cmd = input("\n> ").strip().split()
        if not cmd: continue
        
        if cmd[0] == 'back': break
        if cmd[0] == 'edit' and len(cmd) >= 3:
            key = cmd[1]
            val = cmd[2]
            # Try to cast to int if current is int
            if key in defaults:
                if isinstance(defaults[key], int):
                    try: val = int(val)
                    except: pass
                elif isinstance(defaults[key], bool):
                     val = (val.lower() == 'true')
                cfg.update_default(key, val)
            else:
                print(f"Unknown key: {key}")
                time.sleep(1)

def main():
    # Setup Dirs
    for d in [INPUT_DIR, OUTPUT_RANGES_DIR, OUTPUT_FINAL_DIR, "Config"]:
        if not os.path.exists(d): os.makedirs(d)
        
    cfg = ConfigManager()
    tester = IPTester(cfg)
    generator = IPGenerator(tester)
    
    while True:
        print_header("Main Menu")
        print("  1. Scan IP Ranges (Templates / Files)")
        print("  2. Scan IPs (Direct Input)")
        print("  3. Settings")
        print("  4. Exit")
        
        choice = input("\nSelect: ").strip()
        
        if choice == '1':
            menu_scan_ip_ranges(cfg, tester, generator)
            input("\nPress Enter to continue...")
        elif choice == '2':
            menu_scan_ips(cfg, tester)
            input("\nPress Enter to continue...")
        elif choice == '3':
            menu_settings(cfg)
        elif choice == '4':
            print("Bye!")
            sys.exit(0)

if __name__ == "__main__":
    main()
