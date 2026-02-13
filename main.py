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
import shutil
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

# --- Utils ---

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
    print(f"{Colors.HEADER} {title.center(58)} {Colors.ENDC}")
    print(f"{Colors.HEADER}={'='*60}{Colors.ENDC}")
    print()

def terminal_menu(options, title=None):
    """
    Renders a menu with arrow key navigation.
    options: list of strings or tuples (key, display_text)
    Returns: index of selected option
    """
    cursor_idx = 0
    if title: print_header(title)
    
    # Normalize options to list of strings for display
    display_options = []
    for opt in options:
        if isinstance(opt, tuple): display_options.append(opt[1])
        else: display_options.append(str(opt))
        
    while True:
        if title: 
            clear_screen()
            print_header(title)
        else:
            # If no title, we assume caller handles clearing/header or we just print menu
            # But valid TUI usually wipes screen.
            # Let's enforce clear screen if we want smooth redraw
            print("\033[H", end="") # Move to home if supported, else clear
            # Fallback to clear if title wasn't passed but we need redraw
            pass

        # Print Menu
        for i, opt in enumerate(display_options):
            if i == cursor_idx:
                print(f"{Colors.CYAN} > {opt} {Colors.ENDC}")
            else:
                print(f"   {opt}")
        
        print(f"\n{Colors.CYAN}Use [Up/Down] to Navigate, [Enter] to Select{Colors.ENDC}")
        
        key = get_key()
        if key == 'UP':
            cursor_idx = (cursor_idx - 1) % len(options)
        elif key == 'DOWN':
            cursor_idx = (cursor_idx + 1) % len(options)
        elif key == 'ENTER':
            return cursor_idx
        elif key == 'ESC':
            return -1 # Cancel/Back convention


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

    def scan_ips(self, ips, settings, output_dir=OUTPUT_FINAL_DIR, resume_data=None, sources_info=None, source_files=None, interactive_confirm_save=False):
        """
        ips: list of IP strings
        settings: dict
        resume_data: dict containing previous results if resuming
        sources_info: list of strings describing sources (e.g. ['CloudFlare', 'Fastly']) or dict {ip: provider}
        source_files: list of file paths used as input (for backup)
        interactive_confirm_save: if True, prints results table after scan and confirmation to keep file
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
            
            total_session = len(ips)
            lock = threading.Lock()
            
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
                for ip in ips:
                    if state.stopped: break
                    while state.paused: time.sleep(0.2)
                    
                    ft = executor.submit(task, ip)
                    futures[ft] = ip
                
                # As Completed
                for future in as_completed(futures):
                    ip_processed = futures[future]
                    
                    try:
                        res = future.result()
                    except: res = None
                    
                    if not res: continue # Task was stopped or failed
                    
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
            
            # Interactive Small Batch Confirmation
            if interactive_confirm_save and not state.stopped:
                 print(f"\n{Colors.HEADER}--- Scan Results ---{Colors.ENDC}")
                 print(f"{'IP':<20} | {'Ping':<8} | {'Status'}")
                 print("-" * 50)
                 for r in results:
                      status_col = Colors.GREEN if r['status']=='SUCCESS' else Colors.FAIL
                      print(f"{r['ip']:<20} | {str(r['latency_ms'])+'ms':<8} | {status_col}{r['status']}{Colors.ENDC}")
                      
                 if input("\nSave results to file? (y/N): ").lower() != 'y':
                      try: os.remove(filepath)
                      except: pass
                      print("Results discarded.")
                      return

            # --- Checkpoint & Final Save ---
            
            if state.save_progress and state.stopped:
                 # Calculate remaining IPs
                 scanned_set = set(r['ip'] for r in results)
                 remaining = [ip for ip in ips if ip not in scanned_set]
                 
                 print(f"Creating Checkpoint... ({len(remaining)} IPs remaining)")
                 if not os.path.exists(CHECKPOINTS_DIR): os.makedirs(CHECKPOINTS_DIR)
                 
                 # Backup Logic
                 backup_files_paths = []
                 if source_files:
                     # Create a backup folder for this checkpoint
                     safe_ts = os.path.basename(filename).replace('.', '_').replace(':', '')
                     backup_dir = os.path.join(CHECKPOINTS_DIR, f"Backup_{safe_ts}")
                     if not os.path.exists(backup_dir): os.makedirs(backup_dir)
                     
                     print(f"Backing up {len(source_files)} source files...")
                     for sf in source_files:
                         try:
                             if os.path.exists(sf):
                                 dest = os.path.join(backup_dir, os.path.basename(sf))
                                 shutil.copy2(sf, dest)
                                 backup_files_paths.append(dest)
                         except Exception as e:
                             print(f"Warning: Failed to backup {sf}: {e}")
                 
                 cp_filename = f"Checkpoint_{os.path.basename(filename)}.json"
                 cp_path = os.path.join(CHECKPOINTS_DIR, cp_filename)
                 
                 checkpoint = {
                     "timestamp": datetime.now().isoformat(),
                     "filename": filename,
                     "settings": settings,
                     "sources_info": sources_info, 
                     "results": results, 
                     "backup_files": backup_files_paths,
                     "remaining_ips": remaining if not backup_files_paths else [] # Optimize JSON if backed up
                 }
                 
                 with open(cp_path, 'w') as f:
                     json.dump(checkpoint, f, indent=2)
                 print(f"{Colors.GREEN}Checkpoint saved to: {cp_path}{Colors.ENDC}")
                 if backup_files_paths:
                     print(f"{Colors.CYAN}Source files backed up to: {backup_dir}{Colors.ENDC}")

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

    def generate_and_save(self, cidrs_data, settings, output_dir=OUTPUT_RANGES_DIR):
        if not os.path.exists(output_dir): os.makedirs(output_dir)
        
        generated_files = []
        
        for item in cidrs_data:
            cidr = item['cidr']
            prefix = item.get('prefix', 'Range')
            
            print(f"Generating IPs for {Colors.BOLD}{cidr}{Colors.ENDC} ({prefix})...")
            
            # Warn if IPv6 range is too big
            try:
                network = ipaddress.ip_network(cidr.strip(), strict=False)
                if network.version == 6 and network.num_addresses > 1000000:
                    print(f"  {Colors.WARNING}Skipping {cidr}: Range too large for file output (>1M){Colors.ENDC}")
                    continue
            except: pass

            ips = self.expand_cidr(cidr, settings.get('ip_range_level', 'Short'))
            
            if not ips:
                print(f"  {Colors.FAIL}Invalid CIDR/IP: {cidr}{Colors.ENDC}")
                continue
                
            safe_cidr = cidr.replace('/', '_').replace(':', '')
            filename = f"{prefix}_{safe_cidr}.txt"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'w') as f:
                for ip in ips: f.write(ip + '\n')
            
            print(f" -> Saved {len(ips)} IPs to {filename}")
            generated_files.append(filepath)
            
        return generated_files

# --- Menu Functions ---

def get_user_settings_override(current_defaults):
    print("Use default settings? (Enter=Yes, 'n'=Edit)")
    if input("Diff: ").strip().lower() == 'n':
        print(f"Current: {current_defaults}")
        # Simplification: just return defaults for now or implement edit loop
    return current_defaults

def menu_scan_ip_ranges(cfg, tester, generator):
    settings = cfg.get_defaults()
    templates = cfg.get_templates()
    
    options = [
        "1. Templates (Cloudflare, Fastly, etc.)",
        "2. File Input (List of CIDRs)",
        "3. Terminal Input (Manual)",
        "4. Back"
    ]
    
    idx = terminal_menu(options, "Generate & Scan IP Ranges")
    if idx == 3 or idx == -1: return
    
    targets = [] # List of {'cidr': str, 'prefix': str}
    
    if idx == 0:
        t_keys = list(templates.keys())
        templ_options = [f"{i+1}. {t}" for i, t in enumerate(t_keys)]
        templ_options.append("3. All Templates")
        
        sel_idx = terminal_menu(templ_options, "Select Template")
        
        if sel_idx == -1: return # Back
        
        if sel_idx == len(t_keys): # All Templates (Last option)
            selected_keys = t_keys
        else:
            selected_keys = [t_keys[sel_idx]]
            
        for key in selected_keys:
            cidrs = templates[key]
            for c in cidrs: targets.append({'cidr': c, 'prefix': key})
            
    elif idx == 1:
        files = terminal_file_selector(INPUT_DIR)
        for f in files:
            try:
                with open(f, 'r') as fh:
                    for line in fh:
                        line = line.strip()
                        if line: targets.append({'cidr': line, 'prefix': 'CustomFile'})
            except: pass

    elif idx == 2: # Terminal Input
        inp = input("\nEnter IPs/CIDRs (comma separated): ")
        parts = [p.strip() for p in inp.split(',') if p.strip()]
        for p in parts:
             targets.append({'cidr': p, 'prefix': 'Manual'})
             
    if not targets:
        print("No targets selected.")
        time.sleep(1)
        return

    # Pre-Scan Check (Optional workflow improvement: skip for now or make quicker)
    # User said "Pinging and Generating ... wont work now", implied interruptions.
    # Let's just generate directly as per "Fix Generation Workflow".
    
    working_targets = targets
    
    # Generate
    generated_files = generator.generate_and_save(working_targets, settings)
    
    if generated_files:
        print("\nRange Generation Complete.")
        # Pause to let user see the output before clearing screen
        input("Press Enter to continue...")
        
        scan_opts = ["1. Start Scanning Now", "2. Return to Menu"]
        s_idx = terminal_menu(scan_opts, "Scan Generated Ranges?")
        
        if s_idx == 0:
            all_ips = []
            ip_provider_map = {}
            
            for gf in generated_files:
                # Parse provider from filename prefix
                fname = os.path.basename(gf)
                parts = fname.split('_')
                provider = parts[0] if len(parts) > 1 else "Unknown"
                
                try:
                    with open(gf, 'r') as f:
                        lines = [line.strip() for line in f if line.strip()]
                        all_ips.extend(lines)
                        for ip in lines: ip_provider_map[ip] = provider
                except: pass
            
            # Pass generated_files as source_files for backup
            tester.scan_ips(all_ips, settings, sources_info=ip_provider_map, source_files=generated_files)

def menu_scan_ips(cfg, tester):
    options = [
        "1. Terminal Input",
        "2. File Input",
        "3. Resume Checkpoint",
        "4. Back"
    ]
    
    idx = terminal_menu(options, "Scan IPs (Direct)")
    if idx == 3 or idx == -1: return
    
    if idx == 2:
        # Resume Logic
        if not os.path.exists(CHECKPOINTS_DIR):
             print("No Checkpoints found.")
             time.sleep(1)
             return
             
        files = terminal_file_selector(CHECKPOINTS_DIR, extensions=['.json'])
        if not files: return
        
        # Load first selected
        cp_path = files[0]
        try:
            with open(cp_path, 'r') as f: cp = json.load(f)
            
            resume_ips = []
            backup_files = cp.get('backup_files', [])
            
            if backup_files:
                print(f"Loading IPs from {len(backup_files)} backup files...")
                all_backed_up_ips = []
                for bf in backup_files:
                    if os.path.exists(bf):
                        # Use load_file logic (needs to be accessible or duplicated simpler)
                        # load_file is global.
                        for d in load_file(bf):
                            if 'ip' in d: all_backed_up_ips.append(d['ip'])
                    else:
                        print(f"Warning: Backup file missing: {bf}")
                
                # Filter results
                scanned_set = set(r['ip'] for r in cp.get('results', []))
                resume_ips = [ip for ip in all_backed_up_ips if ip not in scanned_set]
                print(f"Reconstructed {len(resume_ips)} remaining IPs from backups.")
                
            elif 'remaining_ips' in cp:
                resume_ips = cp['remaining_ips']
                print(f"Resuming {len(resume_ips)} IPs from checkpoint data.")
            else:
                print("Invalid checkpoint: No IPs found.")
                time.sleep(1)
                return

            print(f"Resuming {cp['filename']} ({cp['timestamp']})")
            
            # Resume directly without asking for settings override
            tester.scan_ips(resume_ips, cp['settings'], resume_data=cp, sources_info=cp.get('sources_info'), source_files=backup_files)
            
        except Exception as e:
            print(f"Error resuming: {e}")
            time.sleep(2)
        return

    ips_to_scan = []
    
    selected_files = []
    if idx == 0:
        inp = input("Enter IP (or comma separated): ")
        ips_to_scan = [i.strip() for i in inp.split(',') if i.strip()]
    elif idx == 1:
        files = terminal_file_selector(INPUT_DIR)
        selected_files = files # Store for passing to scan_ips
        for f in files:
            data = load_file(f)
            for d in data:
                if 'ip' in d: ips_to_scan.append(d['ip'])
                
    if not ips_to_scan: return
        
    # No settings override prompt
    settings = cfg.get_defaults()
    
    # Check for interactive small batch
    is_interactive = (idx == 0 and len(ips_to_scan) < 10)
    
    tester.scan_ips(ips_to_scan, settings, source_files=selected_files, interactive_confirm_save=is_interactive)

def menu_settings(cfg):
    while True:
        defaults = cfg.get_defaults()
        # Respect JSON order (Python 3.7+ preserves insertion order)
        keys = list(defaults.keys())
        
        # Hide internal/managed keys
        keys = [k for k in keys if k not in ['sources']]
        
        options = []
        for k in keys:
            val = defaults[k]
            # Colorize: Key (Cyan), Value (Green)
            disp = f"{Colors.CYAN}{k}{Colors.ENDC}: {Colors.GREEN}{val}{Colors.ENDC}"
            options.append((k, disp))
            
        options.append(("", f"{Colors.FAIL}Back{Colors.ENDC}"))
        
        idx = terminal_menu(options, "Global Settings (Select to Edit)")
        
        if idx == len(options) - 1 or idx == -1: return
        
        key = keys[idx]
        current_val = defaults[key]
        
        print(f"\nEditing {Colors.BOLD}{key}{Colors.ENDC}")
        print(f"Current Value: {current_val}")
        
        final_val = None
        
        # ComboBox Logic for specific keys
        if key == 'port':
            common_ports = [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096]
            opts = [str(p) for p in common_ports]
            opts.append("Custom")
            p_idx = terminal_menu(opts, f"Select Port (Current: {current_val})")
            if p_idx == -1: continue
            if p_idx == len(opts) - 1: # Custom
                val = input("Enter Custom Port: ").strip()
                if val.isdigit(): final_val = int(val)
            else:
                final_val = common_ports[p_idx]
                
        elif key == 'protocol':
            protos = ['tcp', 'ws', 'grpc', 'kcp', 'quic', 'http', 'https', 'httpupgrade', 'splithttp', 'xhttp']
            opts = protos
            p_idx = terminal_menu(opts, f"Select Protocol (Current: {current_val})")
            if p_idx != -1: final_val = protos[p_idx]
            
        elif key == 'ip_range_level':
            levels = ['Short', 'Medium', 'Full']
            l_idx = terminal_menu(levels, f"Select Range Level (Current: {current_val})")
            if l_idx != -1: final_val = levels[l_idx]
            
        elif key == 'output_format':
            formats = ['json', 'csv', 'txt']
            f_idx = terminal_menu(formats, f"Select Output Format (Current: {current_val})")
            if f_idx != -1: final_val = formats[f_idx]
            
        else:
            # Standard Text Input
            new_val = input("Enter New Value (Enter to cancel): ").strip()
            if new_val:
                # Type inference
                if isinstance(current_val, bool):
                     if new_val.lower() in ['true', '1', 'yes', 'y']: final_val = True
                     elif new_val.lower() in ['false', '0', 'no', 'n']: final_val = False
                elif isinstance(current_val, int):
                    if new_val.isdigit(): final_val = int(new_val)
                else:
                    final_val = new_val

        if final_val is not None:
            cfg.update_default(key, final_val)
            print("Updated.")
            time.sleep(0.5)

def main_menu():
    cfg = ConfigManager()
    tester = IPTester(cfg)
    generator = IPGenerator(tester)
    
    # Ensure Dirs
    for d in [INPUT_DIR, TEMP_DIR, OUTPUT_RANGES_DIR, OUTPUT_FINAL_DIR]:
        if not os.path.exists(d): os.makedirs(d)

    options = [
        "1. Scan IP Ranges (Generate & Scan)",
        "2. Scan IPs (Direct Input/File/Resume)",
        "3. Settings",
        "4. Exit"
    ]

    while True:
        idx = terminal_menu(options, "Py IP Range Scanner")
        
        if idx == 0: 
            menu_scan_ip_ranges(cfg, tester, generator)
        elif idx == 1: 
            menu_scan_ips(cfg, tester)
        elif idx == 2: 
            menu_settings(cfg)
        elif idx == 3 or idx == -1:
            print("Goodbye!")
            break

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nForce Quit.")
