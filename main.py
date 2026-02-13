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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import msvcrt

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
CHECKPOINTS_DIR = "Checkpoints"

# Enable VT100 for Windows 10/11
os.system('color')

# --- Utils (Merged) ---

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_key():
    """Reads a key press and returns a unified key code."""
    key = msvcrt.getch()
    if key in (b'\x00', b'\xe0'):
        # Arrow keys or special function keys
        key = msvcrt.getch()
        if key == b'H': return 'UP'
        if key == b'P': return 'DOWN'
        if key == b'M': return 'RIGHT'
        if key == b'K': return 'LEFT'
    elif key == b'\r': return 'ENTER'
    elif key == b' ': return 'SPACE'
    elif key == b'\x08': return 'BACKSPACE'
    elif key == b'\x03': return 'CTRL_C'
    elif key == b'\x1b': return 'ESC'
    return None

def terminal_file_selector(base_dir=".", extensions=None):
    """
    Interactive TUI file explorer.
    """
    current_dir = os.path.abspath(base_dir)
    selected_files = []
    cursor_idx = 0
    msg = ""

    while True:
        try:
            all_files = os.listdir(current_dir)
        except PermissionError:
            msg = f"Permission Denied: {current_dir}"
            current_dir = os.path.dirname(current_dir)
            continue
            
        dirs = [d for d in all_files if os.path.isdir(os.path.join(current_dir, d))]
        files = [f for f in all_files if os.path.isfile(os.path.join(current_dir, f))]
        
        if extensions:
             files = [f for f in files if any(f.lower().endswith(ext.lower()) for ext in extensions)]
             
        dirs.sort()
        files.sort()
        
        items = []
        if os.path.dirname(current_dir) != current_dir:
             items.append(("UP", "..", "[..] Go Up", os.path.dirname(current_dir)))
             
        for d in dirs:
            items.append(("DIR", d, f"[{d}]", os.path.join(current_dir, d)))
            
        for f in files:
            fpath = os.path.join(current_dir, f)
            is_selected = fpath in selected_files
            mark = "[*]" if is_selected else "[ ]"
            items.append(("FILE", f, f"{mark} {f}", fpath))
            
        HEADER_ITEMS = [("DONE", "Done", ">> FINISH SELECTION <<", None)]
        full_options = HEADER_ITEMS + items
        
        if cursor_idx >= len(full_options): cursor_idx = len(full_options) - 1
        if cursor_idx < 0: cursor_idx = 0
            
        clear_screen()
        print(f"--- File Explorer: {current_dir} ---")
        if msg:
            print(f"   > {msg}")
            msg = ""
            
        print(f"Selected: {len(selected_files)} files")
        print("Controls: [Up/Down] Move | [Space] Select/Deselect | [Enter] Enter Dir/Confirm | [Backspace] Go Up")
        print("-" * 50)
        
        MAX_H = 20
        start_slice = max(0, cursor_idx - MAX_H // 2)
        end_slice = min(len(full_options), start_slice + MAX_H)
        
        for i in range(start_slice, end_slice):
            opt = full_options[i]
            prefix = " > " if i == cursor_idx else "   "
            print(f"{prefix}{opt[2]}")
            
        if end_slice < len(full_options):
            print("   ... (more items) ...")

        action = get_key()
        
        if action == 'UP': cursor_idx = max(0, cursor_idx - 1)
        elif action == 'DOWN': cursor_idx = min(len(full_options) - 1, cursor_idx + 1)
        elif action == 'SPACE':
            current_opt = full_options[cursor_idx]
            if current_opt[0] == 'FILE':
                fpath = current_opt[3]
                if fpath in selected_files: selected_files.remove(fpath)
                else: selected_files.append(fpath)
            elif current_opt[0] == 'DONE': return selected_files
        elif action == 'ENTER':
            current_opt = full_options[cursor_idx]
            if current_opt[0] in ['DIR', 'UP']:
                current_dir = current_opt[3]
                cursor_idx = 0
            elif current_opt[0] == 'DONE': return selected_files
            elif current_opt[0] == 'FILE':
                fpath = current_opt[3]
                if fpath in selected_files: selected_files.remove(fpath)
                else: selected_files.append(fpath)
        elif action in ['BACKSPACE', 'LEFT']:
             parent = os.path.dirname(current_dir)
             if parent != current_dir:
                 current_dir = parent
                 cursor_idx = 0
        elif action == 'CTRL_C':
            print("\nCancelled.")
            return [] 

def load_file(filepath):
    """Loads content from a file (JSON, CSV, or TXT)."""
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return []
        
    ext = os.path.splitext(filepath)[1].lower()
    data = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            if ext == '.json':
                content = json.load(f)
                if isinstance(content, list):
                    data.extend(content)
            elif ext == '.csv':
                reader = csv.DictReader(f)
                for row in reader:
                    data.append(row)
            elif ext == '.txt':
                 for line in f:
                    line = line.strip()
                    if not line: continue
                    parts = line.split('|')
                    entry = {"ip": parts[0].strip()}
                    if len(parts) > 1:
                        rest = [p.strip() for p in parts[1:]]
                        for r in rest:
                             if r.isdigit() or r.replace('ms','').strip().isdigit():
                                 entry['latency_ms'] = int(r.replace('ms','').strip())
                             elif r.upper() in ['SUCCESS', 'FAIL', 'OK', 'ERROR']:
                                 entry['status'] = r.upper()
                    data.append(entry)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
    return data

def print_header(title="IP Range Generator"):
    clear_screen()
    print(f"{Colors.HEADER}={'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{title.center(60)}{Colors.ENDC}")
    print(f"{Colors.HEADER}={'='*60}{Colors.ENDC}")
    print()

# --- Core Logic ---

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
        print(f"\n{Colors.WARNING} [STOPPING] Saving checkpoint and results...{Colors.ENDC}")

    def stop_no_save(self):
        self.stopped = True
        self.save_progress = False
        print(f"\n{Colors.FAIL} [STOPPING] Exiting without saving remaining queue...{Colors.ENDC}")

class ConfigManager:
    def __init__(self):
        self.config = self.load_config()
        
    def load_config(self):
        if not os.path.exists(CONFIG_FILE):
             return {"defaults": {}, "templates": {}}
        try:
            with open(CONFIG_FILE, 'r') as f:
                content = f.read()
                clean_lines = []
                for line in content.splitlines():
                    if '//' in line and "://" not in line:
                         line = line.split('//')[0]
                    clean_lines.append(line)
                clean_content = '\n'.join(clean_lines)
                return json.loads(clean_content)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {"defaults": {}, "templates": {}}

    def check_for_changes(self, current_settings):
        new_config = self.load_config()
        new_defaults = new_config.get('defaults', {})
        diff = {}
        for k, v in new_defaults.items():
            if k in current_settings and current_settings[k] != v:
                diff[k] = {"old": current_settings[k], "new": v}
        return diff, new_defaults

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
            print("Settings saved.")
        except Exception as e:
            print(f"Error saving config: {e}")

    def get_defaults(self): return self.config.get('defaults', {})
    def get_templates(self): return self.config.get('templates', {})
    
    def update_default(self, key, value):
        self.config.setdefault('defaults', {})[key] = value
        self.save_config()

class IPTester:
    def __init__(self, config_manager):
        self.cfg = config_manager
        self.defaults = self.cfg.get_defaults()
        
    def get_socket_family(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            return socket.AF_INET6 if addr.version == 6 else socket.AF_INET
        except ValueError:
            return socket.AF_INET

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
        except: return None

    def test_http(self, ip, port, timeout, protocol="http"):
        formatted_ip = f"[{ip}]" if ":" in ip else ip
        url = f"{protocol}://{formatted_ip}:{port}"
        try:
            start_time = time.time()
            requests.get(url, timeout=timeout)
            end_time = time.time()
            return int((end_time - start_time) * 1000)
        except: return None

    def test_udp(self, ip, port, timeout):
        family = self.get_socket_family(ip)
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            start_time = time.time()
            s.connect((ip, port))
            s.send(b'')
            s.recv(1)
            end_time = time.time()
            s.close()
            return int((end_time - start_time) * 1000)
        except: return None

    def run_test(self, ip, settings):
        proto = settings.get('protocol', 'tcp').lower()
        port = int(settings.get('port', 443))
        timeout = int(settings.get('timeout', 1000)) / 1000.0
        
        tcp_protos = ['tcp', 'ws', 'grpc', 'httpupgrade', 'splithttp', 'xhttp']
        if proto in tcp_protos: return self.test_tcp(ip, port, timeout)
        elif proto in ['http', 'https']: return self.test_http(ip, port, timeout, proto)
        elif proto in ['udp', 'kcp', 'quic']: return self.test_udp(ip, port, timeout)
        return None

    def scan_ips(self, ips, settings, output_dir=OUTPUT_FINAL_DIR, resume_data=None, sources_info=None):
        """
        ips: list of IP strings
        settings: dict
        resume_data: dict containing previous results if resuming
        sources_info: list of strings describing sources (e.g. ['CloudFlare', 'Fastly']) or dict {ip: provider}
        """
        print(f"\n{Colors.HEADER}Starting Scan on {len(ips)} IPs...{Colors.ENDC}")
        print(f"{Colors.CYAN}Controls: [P]ause | [S]top & Save | [Q]uit (No Save){Colors.ENDC}")
        
        max_threads = settings.get('threads', 100)
        output_format = settings.get('output_format', 'txt')
        
        # Setup File Path
        if resume_data and 'filename' in resume_data:
             filename = resume_data['filename']
             results = resume_data.get('results', [])
             print(f"{Colors.GREEN}Resuming previous scan with {len(results)} existing results.{Colors.ENDC}")
        else:
             ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
             filename = f"Scan_{ts}.{output_format}"
             results = []

        filepath = os.path.join(output_dir, filename)
        
        # If we have a sources map (for provider tagging)
        # sources_info can be a list of source names or a dict map.
        # If it's just a set of sources for the whole scan, we store it in metadata.
        # Check if we have per-IP provider info (from filename parsing earlier).
        ip_provider_map = {}
        scan_sources = set()
        
        if isinstance(sources_info, dict):
             ip_provider_map = sources_info
             scan_sources = set(sources_info.values())
        elif isinstance(sources_info, list):
             scan_sources = set(sources_info)
        
        # Add Sources to settings/metadata for output
        settings['sources'] = list(scan_sources)

        state = ScanState()
        
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

        # Queue tracking for checkpoint
        # We need to know which IPs are pending.
        # ips list contains ONLY the IPs to be scanned (already filtered if resuming).
        # We will track processed IPs.
        processed_count = 0 
        
        try:
            f_handle = None
            csv_writer = None
            if output_format in ['txt', 'csv']:
                f_handle = open(filepath, 'a', newline='')
            
            if output_format == 'csv':
                csv_writer = csv.DictWriter(f_handle, fieldnames=['ip', 'latency_ms', 'status', 'provider'])
                if not resume_data: csv_writer.writeheader()
            elif output_format == 'json':
                json_freq = settings.get('json_update_interval', 10000)
                print(f"{Colors.CYAN} [i] JSON format selected. File will be updated every {json_freq} IPs.{Colors.ENDC}")

            completed = 0
            success_count = 0
            
            # If resuming, update counts
            if resume_data:
                 for r in results:
                      if r['status'] == 'SUCCESS': success_count += 1
                 # completed count in this run starts at 0, total display can include prev?
                 # Let's keep "completed" as "processed in this session".
            
            total_session = len(ips)
            lock = threading.Lock()
            
            # Use an iterator to submit tasks so we can robustly save state
            # ThreadPoolExecutor doesn't give us list of pending easily.
            # So we iterate ips.
            
            # Checkpoint Data
            pending_ips = ips[:] 
            
            def task(ip):
                while state.paused:
                    time.sleep(0.5)
                    if state.stopped: return None
                if state.stopped: return None
                
                ping = self.run_test(ip, settings)
                status = "SUCCESS" if ping is not None and ping <= settings.get('max_ping', 1000) else "FAIL"
                
                res = {'ip': ip, 'latency_ms': ping if ping is not None else 0, 'status': status}
                
                # Tag Provider
                if ip in ip_provider_map:
                    res['provider'] = ip_provider_map[ip]
                
                return res

            futures = {} # Future -> IP
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Submit initial batch or all?
                # submitting all 1M IPs keeps them in memory. 
                # For checkpointing "remaining", we just need to know what didn't finish.
                for ip in ips:
                    if state.stopped: break
                    while state.paused: time.sleep(0.2)
                    
                    ft = executor.submit(task, ip)
                    futures[ft] = ip
                
                # As Completed
                for future in as_completed(futures):
                    ip_processed = futures[future]
                    
                    # Remove from pending list (slow for large lists, better to use set or index)
                    # Optimization: pending_ips is not touched here, we calculate it at Stop.
                    # Actually, if we stop, we want IPs that were NOT completed.
                    # We can use a set of completed IPs.
                    
                    try:
                        res = future.result()
                    except: res = None
                    
                    if not res: continue # Task was stopped or failed
                    
                    # Mark as done for checkpoint calculation
                    # We will simply subtract all 'results' IPs from original list if needed,
                    # or better: we won't submit new tasks if stopped.
                    # The `pending` list at the end = `ips` - `completed_ips`.
                    
                    with lock:
                        completed += 1
                        processed_count += 1
                        if res['status'] == 'SUCCESS': success_count += 1
                        
                        results.append(res)
                        
                        sys.stdout.write(f"\r[{completed}/{total_session}] {Colors.BLUE}Scanning...{Colors.ENDC} {Colors.GREEN}Success: {success_count}{Colors.ENDC}")
                        sys.stdout.flush()
                        
                        should_save = res['status'] == 'SUCCESS' or settings.get('save_failed', False)
                        if should_save:
                            if f_handle:
                                if output_format == 'csv': csv_writer.writerow(res)
                                elif output_format == 'txt': 
                                    prov = f" | {res.get('provider','')}" if 'provider' in res else ""
                                    f_handle.write(f"{res['ip']} | {res['latency_ms']}ms | {res['status']}{prov}\n")
                        
                        # Check settings & periodic save logic
                        check_interval = settings.get('settings_check_interval', 1000)
                        if completed % check_interval == 0:
                             diff, new_defaults = self.cfg.check_for_changes(settings)
                             if diff:
                                 if not state.paused:
                                     state.paused = True
                                     print(f"\n{Colors.WARNING} [!] Settings change detected! Pausing...{Colors.ENDC}")
                                     input(f"Press Enter to resume (Changes auto-applied next run if you edit config)...")
                                     # Simple resume for now as full logic is complex inside loop
                                     state.paused = False

                        if output_format == 'json':
                            interval = settings.get('json_update_interval', 10000)
                            if completed % interval == 0:
                                try:
                                    # Filter and Clean Results for Dump
                                    save_all = settings.get('save_failed', False)
                                    dump_results = []
                                    for r in results:
                                        if r['status'] == 'SUCCESS' or save_all:
                                            item = r.copy()
                                            if not save_all and 'status' in item: del item['status']
                                            dump_results.append(item)
                                    
                                    dump_results.sort(key=lambda item: (0 if item.get('status','SUCCESS') == 'SUCCESS' else 1, item['latency_ms'] if item['latency_ms'] is not None else float('inf')))
                                    out = {"settings": settings, "results": dump_results}
                                    with open(filepath, 'w') as f: json.dump(out, f, indent=2)
                                except: pass
                        elif output_format == 'txt' and f_handle:
                             if completed % settings.get('txt_update_interval', 1000) == 0: f_handle.flush()
            
            # End of loop
            print(f"\n{Colors.BOLD}Scan Finished or Stopped.{Colors.ENDC}")
            if f_handle: f_handle.close()
            
            # --- Checkpoint & Final Save ---
            
            if state.save_progress and state.stopped:
                 # Calculate remaining IPs
                 # We have `ips` (input to this function) and `results` (what finished).
                 # We need to save `ips` that are NOT in `results`.
                 # Note: results contain ALL attempts including FAILS, which is correct for checkpoint tracking.
                 scanned_set = set(r['ip'] for r in results)
                 remaining = [ip for ip in ips if ip not in scanned_set]
                 
                 print(f"Creating Checkpoint... ({len(remaining)} IPs remaining)")
                 if not os.path.exists(CHECKPOINTS_DIR): os.makedirs(CHECKPOINTS_DIR)
                 
                 cp_filename = f"Checkpoint_{os.path.basename(filename)}.json"
                 cp_path = os.path.join(CHECKPOINTS_DIR, cp_filename)
                 
                 checkpoint = {
                     "timestamp": datetime.now().isoformat(),
                     "filename": filename,
                     "settings": settings,
                     "sources_info": sources_info, # Save source map
                     "results": results, # Save ALL results (so we don't lose them)
                     "remaining_ips": remaining
                 }
                 
                 with open(cp_path, 'w') as f:
                     json.dump(checkpoint, f, indent=2)
                 print(f"{Colors.GREEN}Checkpoint saved to: {cp_path}{Colors.ENDC}")

            # Final JSON dump
            if output_format == 'json' and results:
                print("Saving Final JSON report...")
                # Filter and Clean Results for Dump
                save_all = settings.get('save_failed', False)
                dump_results = []
                for r in results:
                    if r['status'] == 'SUCCESS' or save_all:
                        item = r.copy()
                        if not save_all and 'status' in item: del item['status']
                        dump_results.append(item)

                dump_results.sort(key=lambda item: (0 if item.get('status', 'SUCCESS') == 'SUCCESS' else 1, item['latency_ms'] if item['latency_ms'] is not None else float('inf')))
                out = {"settings": settings, "results": dump_results}
                with open(filepath, 'w') as f: json.dump(out, f, indent=2)
            
            print(f"{Colors.GREEN}Results saved to: {filepath}{Colors.ENDC}")

        except Exception as e:
            print(f"\nError in scan: {e}")
        finally:
            state.stopped = True

class IPGenerator:
    def __init__(self, tester):
        self.tester = tester
        
    def expand_cidr(self, cidr, range_level='Short'):
        """
        Expands a CIDR. If input is a single IP (no slash), applies range_level.
        Short=/24 (256), Medium=/20 (4096), Full=/16 (65536).
        """
        if '/' not in cidr:
            # Single IP -> Range
            if range_level == 'Medium': cidr += '/20'
            elif range_level == 'Full': cidr += '/16'
            else: cidr += '/24' # Default Short

        try:
            return [str(ip) for ip in ipaddress.ip_network(cidr.strip(), strict=False)]
        except:
            return []
            
    def get_sample_ip(self, cidr):
        try:
            if '/' not in cidr: return cidr
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            if net.version == 6: return str(net[1]) 
            else:
                if net.num_addresses > 2:
                    idx = random.randint(1, min(net.num_addresses - 2, 100)) 
                    return str(net[idx])
                else: return str(net[0])
        except: return None

    def generate_and_save(self, cidrs_data, settings, output_dir=OUTPUT_RANGES_DIR):
        """
        Generates lists of IPs.
        cidrs_data: List of dicts {'cidr': str, 'prefix': str}
        """
        generated_files = []
        if not os.path.exists(output_dir): os.makedirs(output_dir)

        range_level = settings.get('ip_range_level', 'Short')

        for item in cidrs_data:
            cidr = item['cidr']
            prefix = item.get('prefix', 'Range')
            
            print(f"Generating IPs for {Colors.BOLD}{cidr}{Colors.ENDC} ({prefix})...")
            
            try:
                ctmp = cidr
                if '/' not in ctmp:
                    if range_level == 'Medium': ctmp += '/20'
                    elif range_level == 'Full': ctmp += '/16'
                    else: ctmp += '/24'
                
                net = ipaddress.ip_network(ctmp.strip(), strict=False)
                if net.version == 6 and net.prefixlen < 64: 
                     print(f" {Colors.WARNING}[!] Skipping massive IPv6 range {cidr}.{Colors.ENDC}")
                     continue
            except: pass

            ips = self.expand_cidr(cidr, range_level)
            if not ips: 
                print(f"Invalid CIDR: {cidr}")
                continue
            
            if len(ips) > 1000000:
                print(f" [!] Range {cidr} has {len(ips)} IPs. Large file.")

            safe_cidr = cidr.replace('/', '_').replace(':', '')
            filename = f"{prefix}_{safe_cidr}.txt"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'w') as f:
                for ip in ips: f.write(ip + '\n')
            
            print(f" -> Saved {len(ips)} IPs to {filename}")
            generated_files.append(filepath)
            
        return generated_files

# --- Menu Functions ---

def get_user_settings_override(defaults):
    print_header("Scan Settings")
    print(f"{Colors.HEADER}Current Settings:{Colors.ENDC}")
    for k, v in defaults.items():
        print(f"  {k:<20}: {v}")
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
        
        rl = input(f"IP Range Level ({defaults.get('ip_range_level', 'Short')}): ")
        if rl: new_settings['ip_range_level'] = rl
        
    except Exception as e:
        print(f"Invalid input, using defaults. Error: {e}")
    return new_settings

def menu_scan_ip_ranges(cfg, tester, generator):
    print_header("Scan IP Ranges")
    print(f"{Colors.BOLD}Select Source:{Colors.ENDC}")
    print("  1. Use Templates (CloudFlare/Fastly)")
    print("  2. Select File with Ranges/IPs")
    print("  3. Terminal Input (Manual)")
    print("  4. Back")
    src = input("\nSelect (1-4): ").strip()
    
    if src == '4': return
    
    targets = [] 
    
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
            if 0 < sel <= len(providers): selected_providers = [providers[sel-1]]
            else: selected_providers = providers
        except: selected_providers = providers
        
        defaults = cfg.get_defaults()
        use_ipv6 = defaults.get('ipv6_enabled', False)
        if input(f"Include IPv6 ranges? (Currently {use_ipv6}) (y/n): ").lower() == 'y': use_ipv6 = True
        
        for p in selected_providers:
            p_data = templates[p]
            cidrs = []
            if isinstance(p_data, dict):
                if 'ipv4' in p_data: cidrs.extend(p_data['ipv4'])
                if use_ipv6 and 'ipv6' in p_data: cidrs.extend(p_data['ipv6'])
            elif isinstance(p_data, list):
                cidrs.extend(p_data)
            
            for c in cidrs:
                targets.append({'cidr': c, 'prefix': p})

    elif src == '2':
        files = terminal_file_selector(INPUT_DIR, extensions=['.txt', '.json', '.csv'])
        for f in files:
            data = load_file(f)
            for d in data:
                if 'ip' in d: targets.append({'cidr': d['ip'], 'prefix': 'Range'})

    elif src == '3':
        inp = input("Enter IPs/CIDRs (comma separated): ")
        parts = [p.strip() for p in inp.split(',') if p.strip()]
        for p in parts:
             targets.append({'cidr': p, 'prefix': 'Manual'})
    
    if not targets:
        print("No ranges selected.")
        return

    settings = get_user_settings_override(cfg.get_defaults())

    # Pre-scan Prompt
    do_prescan = True
    if input("\nDo you want to Ping/Filter input IPs first? (Y/n): ").lower() == 'n':
        do_prescan = False

    working_targets = []
    
    if do_prescan:
        print(f"\nPhase 1: Pre-Scanning {len(targets)} Targets...")
        for item in targets:
            cidr = item['cidr']
            sample = generator.get_sample_ip(cidr)
            if not sample: continue
            res = tester.run_test(sample, settings)
            if res:
                print(f"   [{Colors.GREEN}+{Colors.ENDC}] {cidr} seems UP ({res}ms)")
                working_targets.append(item)
            else:
                print(f"   [{Colors.FAIL}-{Colors.ENDC}] {cidr} seems DOWN")
    else:
        working_targets = targets

    if not working_targets:
        print("No working targets found.")
        return

    print(f"\nPhase 2: Generating Files for {len(working_targets)} ranges...")
    generated_files = generator.generate_and_save(working_targets, settings)
    
    if generated_files:
        if input("\nDo you want to scan EACH IP in these ranges? (y/N): ").lower() == 'y':
            all_ips = []
            ip_provider_map = {}
            
            for gf in generated_files:
                # Infer provider from filename: "CloudFlare_Range_..."
                fname = os.path.basename(gf)
                # Simple heuristic: Split by '_' and take first part?
                # User asked for: "Provider Field for Each record".
                # When generated, filename is "Prefix_SafeCIDR.txt".
                # Prefix comes from item['prefix'].
                
                provider = "Unknown"
                if "_" in fname: provider = fname.split('_')[0]
                
                try:
                    with open(gf, 'r') as f:
                        lines = [line.strip() for line in f if line.strip()]
                        all_ips.extend(lines)
                        for ip in lines: ip_provider_map[ip] = provider
                except: pass
            
            tester.scan_ips(all_ips, settings, sources_info=ip_provider_map)

def menu_scan_ips(cfg, tester):
    print_header("Scan IPs (Direct)")
    print("  1. Terminal Input")
    print("  2. File Input")
    print(f"  3. Resume Checkpoint ({Colors.WARNING}New!{Colors.ENDC})")
    print("  4. Back")
    src = input("\nSelect (1-4): ").strip()
    
    if src == '4': return
    
    if src == '3':
        # Resume Logic
        if not os.path.exists(CHECKPOINTS_DIR):
             print("No Checkpoints found.")
             return
             
        files = terminal_file_selector(CHECKPOINTS_DIR, extensions=['.json'])
        if not files: return
        
        # Load first selected
        cp_path = files[0]
        try:
            with open(cp_path, 'r') as f: cp = json.load(f)
            
            # Check structure
            if 'remaining_ips' not in cp:
                print("Invalid checkpoint file.")
                return
                
            print(f"Resuming {cp['filename']} ({cp['timestamp']})")
            print(f"Remaining IPs: {len(cp['remaining_ips'])}")
            
            tester.scan_ips(cp['remaining_ips'], cp['settings'], resume_data=cp, sources_info=cp.get('sources_info'))
            
        except Exception as e:
            print(f"Error resuming: {e}")
        return

    ips_to_scan = []
    
    if src == '1':
        inp = input("Enter IP (or comma separated): ")
        ips_to_scan = [i.strip() for i in inp.split(',') if i.strip()]
    elif src == '2':
        files = terminal_file_selector(INPUT_DIR)
        for f in files:
            data = load_file(f)
            for d in data:
                if 'ip' in d: ips_to_scan.append(d['ip'])
                
    if not ips_to_scan: return
        
    settings = get_user_settings_override(cfg.get_defaults())
    tester.scan_ips(ips_to_scan, settings)

def menu_settings(cfg):
    while True:
        print_header("Global Settings")
        defaults = cfg.get_defaults()
        print(f"{Colors.BOLD}{'Key':<25} {'Value':<20}{Colors.ENDC}")
        print("-" * 50)
        for k, v in defaults.items():
            print(f"{k:<25} {v}")
            
        print(f"\n{Colors.CYAN}Commands:{Colors.ENDC}")
        print("  edit <key> <val>   (e.g., edit threads 200)")
        print("  back               (Return to Main Menu)")
        
        cmd = input("\n> ").strip().split()
        if not cmd: continue
        
        if cmd[0] == 'back': break
        if cmd[0] == 'edit' and len(cmd) >= 3:
            key = cmd[1]
            val = cmd[2]
            if val.isdigit(): val = int(val)
            elif val.lower() == 'true': val = True
            elif val.lower() == 'false': val = False
            
            cfg.update_default(key, val)
            print("Updated.")

def main_menu():
    cfg = ConfigManager()
    tester = IPTester(cfg)
    generator = IPGenerator(tester)
    
    while True:
        print_header("Py IP Range Scanner")
        print("  1. Scan IP Ranges (Generate & Scan)")
        print("  2. Scan IPs (Direct Input/File)")
        print("  3. Settings")
        print("  4. Exit")
        
        choice = input("\nSelect (1-4): ").strip()
        
        if choice == '1': menu_scan_ip_ranges(cfg, tester, generator)
        elif choice == '2': menu_scan_ips(cfg, tester)
        elif choice == '3': menu_settings(cfg)
        elif choice == '4': sys.exit(0)

if __name__ == "__main__":
    try:
        if not os.path.exists(INPUT_DIR): os.makedirs(INPUT_DIR)
        if not os.path.exists(TEMP_DIR): os.makedirs(TEMP_DIR)
        if not os.path.exists(OUTPUT_RANGES_DIR): os.makedirs(OUTPUT_RANGES_DIR)
        if not os.path.exists(OUTPUT_FINAL_DIR): os.makedirs(OUTPUT_FINAL_DIR)
        if not os.path.exists(CHECKPOINTS_DIR): os.makedirs(CHECKPOINTS_DIR)
        main_menu()
    except KeyboardInterrupt:
        print("\nExiting...")

import socket
import random
import ipaddress
import requests
import csv
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import msvcrt

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

# Enable VT100 for Windows 10/11
os.system('color')

# --- Utils (Merged) ---

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_key():
    """Reads a key press and returns a unified key code."""
    key = msvcrt.getch()
    if key in (b'\x00', b'\xe0'):
        # Arrow keys or special function keys
        key = msvcrt.getch()
        if key == b'H': return 'UP'
        if key == b'P': return 'DOWN'
        if key == b'M': return 'RIGHT'
        if key == b'K': return 'LEFT'
    elif key == b'\r': return 'ENTER'
    elif key == b' ': return 'SPACE'
    elif key == b'\x08': return 'BACKSPACE'
    elif key == b'\x03': return 'CTRL_C'
    elif key == b'\x1b': return 'ESC'
    return None

def terminal_file_selector(base_dir=".", extensions=None):
    """
    Interactive TUI file explorer.
    """
    current_dir = os.path.abspath(base_dir)
    selected_files = []
    cursor_idx = 0
    msg = ""

    while True:
        try:
            all_files = os.listdir(current_dir)
        except PermissionError:
            msg = f"Permission Denied: {current_dir}"
            current_dir = os.path.dirname(current_dir)
            continue
            
        dirs = [d for d in all_files if os.path.isdir(os.path.join(current_dir, d))]
        files = [f for f in all_files if os.path.isfile(os.path.join(current_dir, f))]
        
        if extensions:
             files = [f for f in files if any(f.lower().endswith(ext.lower()) for ext in extensions)]
             
        dirs.sort()
        files.sort()
        
        items = []
        if os.path.dirname(current_dir) != current_dir:
             items.append(("UP", "..", "[..] Go Up", os.path.dirname(current_dir)))
             
        for d in dirs:
            items.append(("DIR", d, f"[{d}]", os.path.join(current_dir, d)))
            
        for f in files:
            fpath = os.path.join(current_dir, f)
            is_selected = fpath in selected_files
            mark = "[*]" if is_selected else "[ ]"
            items.append(("FILE", f, f"{mark} {f}", fpath))
            
        HEADER_ITEMS = [("DONE", "Done", ">> FINISH SELECTION <<", None)]
        full_options = HEADER_ITEMS + items
        
        if cursor_idx >= len(full_options): cursor_idx = len(full_options) - 1
        if cursor_idx < 0: cursor_idx = 0
            
        clear_screen()
        print(f"--- File Explorer: {current_dir} ---")
        if msg:
            print(f"   > {msg}")
            msg = ""
            
        print(f"Selected: {len(selected_files)} files")
        print("Controls: [Up/Down] Move | [Space] Select/Deselect | [Enter] Enter Dir/Confirm | [Backspace] Go Up")
        print("-" * 50)
        
        MAX_H = 20
        start_slice = max(0, cursor_idx - MAX_H // 2)
        end_slice = min(len(full_options), start_slice + MAX_H)
        
        for i in range(start_slice, end_slice):
            opt = full_options[i]
            prefix = " > " if i == cursor_idx else "   "
            print(f"{prefix}{opt[2]}")
            
        if end_slice < len(full_options):
            print("   ... (more items) ...")

        action = get_key()
        
        if action == 'UP': cursor_idx = max(0, cursor_idx - 1)
        elif action == 'DOWN': cursor_idx = min(len(full_options) - 1, cursor_idx + 1)
        elif action == 'SPACE':
            current_opt = full_options[cursor_idx]
            if current_opt[0] == 'FILE':
                fpath = current_opt[3]
                if fpath in selected_files: selected_files.remove(fpath)
                else: selected_files.append(fpath)
            elif current_opt[0] == 'DONE': return selected_files
        elif action == 'ENTER':
            current_opt = full_options[cursor_idx]
            if current_opt[0] in ['DIR', 'UP']:
                current_dir = current_opt[3]
                cursor_idx = 0
            elif current_opt[0] == 'DONE': return selected_files
            elif current_opt[0] == 'FILE':
                fpath = current_opt[3]
                if fpath in selected_files: selected_files.remove(fpath)
                else: selected_files.append(fpath)
        elif action in ['BACKSPACE', 'LEFT']:
             parent = os.path.dirname(current_dir)
             if parent != current_dir:
                 current_dir = parent
                 cursor_idx = 0
        elif action == 'CTRL_C':
            print("\nCancelled.")
            return [] # Better to return empty list than exit hard

def load_file(filepath):
    """Loads content from a file (JSON, CSV, or TXT)."""
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return []
        
    ext = os.path.splitext(filepath)[1].lower()
    data = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            if ext == '.json':
                content = json.load(f)
                if isinstance(content, list):
                    data.extend(content)
            elif ext == '.csv':
                reader = csv.DictReader(f)
                for row in reader:
                    data.append(row)
            elif ext == '.txt':
                 for line in f:
                    line = line.strip()
                    if not line: continue
                    parts = line.split('|')
                    entry = {"ip": parts[0].strip()}
                    if len(parts) > 1:
                        rest = [p.strip() for p in parts[1:]]
                        for r in rest:
                             if r.isdigit() or r.replace('ms','').strip().isdigit():
                                 entry['latency_ms'] = int(r.replace('ms','').strip())
                             elif r.upper() in ['SUCCESS', 'FAIL', 'OK', 'ERROR']:
                                 entry['status'] = r.upper()
                    data.append(entry)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
    return data

def print_header(title="IP Range Generator"):
    clear_screen()
    print(f"{Colors.HEADER}={'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{title.center(60)}{Colors.ENDC}")
    print(f"{Colors.HEADER}={'='*60}{Colors.ENDC}")
    print()

# --- Core Logic ---

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
             return {"defaults": {}, "templates": {}}
        try:
            with open(CONFIG_FILE, 'r') as f:
                content = f.read()
                clean_lines = []
                for line in content.splitlines():
                    if '//' in line and "://" not in line:
                         line = line.split('//')[0]
                    clean_lines.append(line)
                clean_content = '\n'.join(clean_lines)
                return json.loads(clean_content)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {"defaults": {}, "templates": {}}

    def check_for_changes(self, current_settings):
        new_config = self.load_config()
        new_defaults = new_config.get('defaults', {})
        diff = {}
        for k, v in new_defaults.items():
            if k in current_settings and current_settings[k] != v:
                diff[k] = {"old": current_settings[k], "new": v}
        return diff, new_defaults

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
            print("Settings saved.")
        except Exception as e:
            print(f"Error saving config: {e}")

    def get_defaults(self): return self.config.get('defaults', {})
    def get_templates(self): return self.config.get('templates', {})
    
    def update_default(self, key, value):
        self.config.setdefault('defaults', {})[key] = value
        self.save_config()

class IPTester:
    def __init__(self, config_manager):
        self.cfg = config_manager
        self.defaults = self.cfg.get_defaults()
        
    def get_socket_family(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            return socket.AF_INET6 if addr.version == 6 else socket.AF_INET
        except ValueError:
            return socket.AF_INET

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
        except: return None

    def test_http(self, ip, port, timeout, protocol="http"):
        formatted_ip = f"[{ip}]" if ":" in ip else ip
        url = f"{protocol}://{formatted_ip}:{port}"
        try:
            start_time = time.time()
            requests.get(url, timeout=timeout)
            end_time = time.time()
            return int((end_time - start_time) * 1000)
        except: return None

    def test_udp(self, ip, port, timeout):
        family = self.get_socket_family(ip)
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            start_time = time.time()
            s.connect((ip, port))
            s.send(b'')
            s.recv(1)
            end_time = time.time()
            s.close()
            return int((end_time - start_time) * 1000)
        except: return None

    def run_test(self, ip, settings):
        proto = settings.get('protocol', 'tcp').lower()
        port = int(settings.get('port', 443))
        timeout = int(settings.get('timeout', 1000)) / 1000.0
        
        tcp_protos = ['tcp', 'ws', 'grpc', 'httpupgrade', 'splithttp', 'xhttp']
        if proto in tcp_protos: return self.test_tcp(ip, port, timeout)
        elif proto in ['http', 'https']: return self.test_http(ip, port, timeout, proto)
        elif proto in ['udp', 'kcp', 'quic']: return self.test_udp(ip, port, timeout)
        return None

    def scan_ips(self, ips, settings, output_dir=OUTPUT_FINAL_DIR):
        print(f"\n{Colors.HEADER}Starting Scan on {len(ips)} IPs...{Colors.ENDC}")
        print(f"{Colors.CYAN}Controls: [P]ause | [S]top & Save | [Q]uit (No Save){Colors.ENDC}")
        
        max_threads = settings.get('threads', 100)
        output_format = settings.get('output_format', 'txt')
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"Scan_{ts}.{output_format}"
        filepath = os.path.join(output_dir, filename)
        
        state = ScanState()
        
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
        try:
            f_handle = None
            csv_writer = None
            if output_format in ['txt', 'csv']:
                f_handle = open(filepath, 'a', newline='')
            
            if output_format == 'csv':
                csv_writer = csv.DictWriter(f_handle, fieldnames=['ip', 'latency_ms', 'status'])
                csv_writer.writeheader()
            elif output_format == 'json':
                json_freq = settings.get('json_update_interval', 10000)
                print(f"{Colors.CYAN} [i] JSON format selected. File will be updated every {json_freq} IPs.{Colors.ENDC}")

            completed = 0
            success_count = 0
            total = len(ips)
            lock = threading.Lock()
            
            def task(ip):
                while state.paused:
                    time.sleep(0.5)
                    if state.stopped: return None
                if state.stopped: return None
                
                ping = self.run_test(ip, settings)
                status = "SUCCESS" if ping is not None and ping <= settings.get('max_ping', 1000) else "FAIL"
                return {'ip': ip, 'latency_ms': ping if ping is not None else 0, 'status': status}

            futures = []
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                for ip in ips:
                    if state.stopped: break
                    while state.paused: time.sleep(0.2)
                    futures.append(executor.submit(task, ip))
                
                for future in as_completed(futures):
                    res = future.result()
                    if not res: continue
                    
                    with lock:
                        completed += 1
                        if res['status'] == 'SUCCESS': success_count += 1
                        
                        sys.stdout.write(f"\r[{completed}/{total}] {Colors.BLUE}Scanning...{Colors.ENDC} {Colors.GREEN}Success: {success_count}{Colors.ENDC}")
                        sys.stdout.flush()
                        
                        should_save = res['status'] == 'SUCCESS' or settings.get('save_failed', False)
                        if should_save:
                            if f_handle:
                                if output_format == 'csv': csv_writer.writerow(res)
                                elif output_format == 'txt': f_handle.write(f"{res['ip']} | {res['latency_ms']}ms | {res['status']}\n")
                            if output_format == 'json':
                                results.append(res)

                        # Check settings & periodic save logic
                        check_interval = settings.get('settings_check_interval', 1000)
                        if completed % check_interval == 0:
                             diff, new_defaults = self.cfg.check_for_changes(settings)
                             if diff:
                                 if not state.paused:
                                     state.paused = True
                                     print(f"\n{Colors.WARNING} [!] Settings change detected! Pausing...{Colors.ENDC}")
                                     print(f"\n{Colors.HEADER}Changed Settings:{Colors.ENDC}")
                                     for k, v in diff.items():
                                         print(f"  {k}: {v['old']} -> {v['new']}")
                                     choice = input(f"\n{Colors.WARNING}Apply changes? (y/N): {Colors.ENDC}").lower()
                                     if choice == 'y':
                                         settings.update(new_defaults)
                                         print(f"{Colors.GREEN}Settings applied!{Colors.ENDC}")
                                         if 'threads' in diff: print(f"{Colors.WARNING} [!] Restart scan to apply new threads.{Colors.ENDC}")
                                     else: print("Changes discarded.")
                                     state.paused = False
                                     print(f"{Colors.GREEN}Resuming...{Colors.ENDC}")

                        if output_format == 'json':
                            interval = settings.get('json_update_interval', 10000)
                            if completed % interval == 0:
                                try:
                                    results.sort(key=lambda item: (0 if item['status'] == 'SUCCESS' else 1, item['latency_ms'] if item['latency_ms'] is not None else float('inf')))
                                    out = {"settings": settings, "results": results}
                                    with open(filepath, 'w') as f: json.dump(out, f, indent=2)
                                except: pass
                        elif output_format == 'txt' and f_handle:
                             if completed % settings.get('txt_update_interval', 1000) == 0: f_handle.flush()
                        elif output_format == 'csv' and f_handle:
                             if completed % settings.get('csv_update_interval', 10000) == 0: f_handle.flush()

            print(f"\n{Colors.BOLD}Scan Finished or Stopped.{Colors.ENDC}")
            if f_handle: f_handle.close()
            if output_format == 'json' and results:
                print("Saving Final JSON report...")
                results.sort(key=lambda item: (0 if item['status'] == 'SUCCESS' else 1, item['latency_ms'] if item['latency_ms'] is not None else float('inf')))
                out = {"settings": settings, "results": results}
                with open(filepath, 'w') as f: json.dump(out, f, indent=2)
            print(f"{Colors.GREEN}Results saved to: {filepath}{Colors.ENDC}")

        except Exception as e:
            print(f"\nError in scan: {e}")
        finally:
            state.stopped = True  # Ensure listener thread terminates

class IPGenerator:
    def __init__(self, tester):
        self.tester = tester
        
    def expand_cidr(self, cidr, range_level='Short'):
        """
        Expands a CIDR. If input is a single IP (no slash), applies range_level.
        Short=/24 (256), Medium=/20 (4096), Full=/16 (65536).
        """
        if '/' not in cidr:
            # Single IP -> Range
            if range_level == 'Medium': cidr += '/20'
            elif range_level == 'Full': cidr += '/16'
            else: cidr += '/24' # Default Short

        try:
            return [str(ip) for ip in ipaddress.ip_network(cidr.strip(), strict=False)]
        except:
            return []
            
    def get_sample_ip(self, cidr):
        try:
            # Handle implied range if needed, but for sampling we just want checking.
            # If it's a single IP without slash, treat as /32 for sampling (check that specific IP).
            # But if we plan to expand it later, checking the IP itself is fine.
            if '/' not in cidr: return cidr
            
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            if net.version == 6: return str(net[1]) 
            else:
                if net.num_addresses > 2:
                    idx = random.randint(1, min(net.num_addresses - 2, 100)) 
                    return str(net[idx])
                else: return str(net[0])
        except: return None

    def generate_and_save(self, cidrs_data, settings, output_dir=OUTPUT_RANGES_DIR):
        """
        Generates lists of IPs.
        cidrs_data: List of dicts {'cidr': str, 'prefix': str}
        """
        generated_files = []
        if not os.path.exists(output_dir): os.makedirs(output_dir)

        range_level = settings.get('ip_range_level', 'Short')

        for item in cidrs_data:
            cidr = item['cidr']
            prefix = item.get('prefix', 'Range')
            
            print(f"Generating IPs for {Colors.BOLD}{cidr}{Colors.ENDC} ({prefix})...")
            
            # Helper to check if it's IPv6 /32 (illegal to expand)
            # If it's single IP, expand_cidr handles it.
            # If it's a massive CIDR, we skip.
            try:
                # Check projected network size
                ctmp = cidr
                if '/' not in ctmp:
                    if range_level == 'Medium': ctmp += '/20'
                    elif range_level == 'Full': ctmp += '/16'
                    else: ctmp += '/24'
                
                net = ipaddress.ip_network(ctmp.strip(), strict=False)
                if net.version == 6 and net.prefixlen < 64: # Limits IPv6 expansion
                     print(f" {Colors.WARNING}[!] Skipping massive IPv6 range {cidr}.{Colors.ENDC}")
                     continue
            except: pass

            ips = self.expand_cidr(cidr, range_level)
            if not ips: 
                print(f"Invalid CIDR: {cidr}")
                continue
            
            if len(ips) > 1000000:
                print(f" [!] Range {cidr} has {len(ips)} IPs. Large file.")

            safe_cidr = cidr.replace('/', '_').replace(':', '')
            filename = f"{prefix}_{safe_cidr}.txt"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'w') as f:
                for ip in ips: f.write(ip + '\n')
            
            print(f" -> Saved {len(ips)} IPs to {filename}")
            generated_files.append(filepath)
            
        return generated_files

# --- Menu Functions ---

def get_user_settings_override(defaults):
    print_header("Scan Settings")
    print(f"{Colors.HEADER}Current Settings:{Colors.ENDC}")
    for k, v in defaults.items():
        print(f"  {k:<20}: {v}")
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
        
        # Add range level to override?
        rl = input(f"IP Range Level ({defaults.get('ip_range_level', 'Short')}): ")
        if rl: new_settings['ip_range_level'] = rl
        
    except Exception as e:
        print(f"Invalid input, using defaults. Error: {e}")
    return new_settings

def menu_scan_ip_ranges(cfg, tester, generator):
    print_header("Scan IP Ranges")
    print(f"{Colors.BOLD}Select Source:{Colors.ENDC}")
    print("  1. Use Templates (CloudFlare/Fastly)")
    print("  2. Select File with Ranges/IPs")
    print("  3. Back")
    src = input("\nSelect (1-3): ").strip()
    
    if src == '3': return
    
    # List of {'cidr': str, 'prefix': str}
    targets = [] 
    
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
            if 0 < sel <= len(providers): selected_providers = [providers[sel-1]]
            else: selected_providers = providers
        except: selected_providers = providers
        
        defaults = cfg.get_defaults()
        use_ipv6 = defaults.get('ipv6_enabled', False)
        if input(f"Include IPv6 ranges? (Currently {use_ipv6}) (y/n): ").lower() == 'y': use_ipv6 = True
        
        for p in selected_providers:
            p_data = templates[p]
            cidrs = []
            if isinstance(p_data, dict):
                if 'ipv4' in p_data: cidrs.extend(p_data['ipv4'])
                if use_ipv6 and 'ipv6' in p_data: cidrs.extend(p_data['ipv6'])
            elif isinstance(p_data, list):
                cidrs.extend(p_data)
            
            for c in cidrs:
                targets.append({'cidr': c, 'prefix': p})

    elif src == '2':
        files = terminal_file_selector(INPUT_DIR, extensions=['.txt', '.json', '.csv'])
        for f in files:
            data = load_file(f)
            # Use 'Range' as prefix or try to guess? User asked for Provider Prefixes for Template Method.
            # For custom files, "Range" is safe.
            for d in data:
                if 'ip' in d: targets.append({'cidr': d['ip'], 'prefix': 'Range'})
    
    if not targets:
        print("No ranges selected.")
        return

    settings = get_user_settings_override(cfg.get_defaults())

    # Pre-scan Prompt
    do_prescan = True
    if input("\nDo you want to Ping/Filter input IPs first? (Y/n): ").lower() == 'n':
        do_prescan = False

    working_targets = []
    
    if do_prescan:
        print(f"\nPhase 1: Pre-Scanning {len(targets)} Targets...")
        for item in targets:
            cidr = item['cidr']
            sample = generator.get_sample_ip(cidr)
            if not sample: continue
            res = tester.run_test(sample, settings)
            if res:
                print(f"   [{Colors.GREEN}+{Colors.ENDC}] {cidr} seems UP ({res}ms)")
                working_targets.append(item)
            else:
                print(f"   [{Colors.FAIL}-{Colors.ENDC}] {cidr} seems DOWN")
    else:
        working_targets = targets

    if not working_targets:
        print("No working targets found.")
        return

    print(f"\nPhase 2: Generating Files for {len(working_targets)} ranges...")
    generated_files = generator.generate_and_save(working_targets, settings)
    
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
            data = load_file(f)
            for d in data:
                if 'ip' in d: ips_to_scan.append(d['ip'])
                
    if not ips_to_scan: return
        
    settings = get_user_settings_override(cfg.get_defaults())
    tester.scan_ips(ips_to_scan, settings)

def menu_settings(cfg):
    while True:
        print_header("Global Settings")
        defaults = cfg.get_defaults()
        print(f"{Colors.BOLD}{'Key':<25} {'Value':<20}{Colors.ENDC}")
        print("-" * 50)
        for k, v in defaults.items():
            print(f"{k:<25} {v}")
            
        print(f"\n{Colors.CYAN}Commands:{Colors.ENDC}")
        print("  edit <key> <val>   (e.g., edit threads 200)")
        print("  back               (Return to Main Menu)")
        
        cmd = input("\n> ").strip().split()
        if not cmd: continue
        
        if cmd[0] == 'back': break
        if cmd[0] == 'edit' and len(cmd) >= 3:
            key = cmd[1]
            val = cmd[2]
            # Type casting
            if val.isdigit(): val = int(val)
            elif val.lower() == 'true': val = True
            elif val.lower() == 'false': val = False
            
            cfg.update_default(key, val)
            print("Updated.")

def main_menu():
    cfg = ConfigManager()
    tester = IPTester(cfg)
    generator = IPGenerator(tester)
    
    while True:
        print_header("Py IP Range Scanner")
        print("  1. Scan IP Ranges (Generate & Scan)")
        print("  2. Scan IPs (Direct Input/File)")
        print("  3. Settings")
        print("  4. Exit")
        
        choice = input("\nSelect (1-4): ").strip()
        
        if choice == '1': menu_scan_ip_ranges(cfg, tester, generator)
        elif choice == '2': menu_scan_ips(cfg, tester)
        elif choice == '3': menu_settings(cfg)
        elif choice == '4': sys.exit(0)

if __name__ == "__main__":
    try:
        if not os.path.exists(INPUT_DIR): os.makedirs(INPUT_DIR)
        if not os.path.exists(TEMP_DIR): os.makedirs(TEMP_DIR)
        if not os.path.exists(OUTPUT_RANGES_DIR): os.makedirs(OUTPUT_RANGES_DIR)
        if not os.path.exists(OUTPUT_FINAL_DIR): os.makedirs(OUTPUT_FINAL_DIR)
        main_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
