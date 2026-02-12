import os
import sys
import msvcrt
import json
import csv

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_key():
    """Reads a key press and returns a unified key code."""
    # This is a blocking call on Windows using msvcrt
    # For arrow keys, it returns a prefix (0x00 or 0xE0) followed by the scancode
    
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
    elif key == b'\x08': return 'BACKSPACE' # Backspace
    elif key == b'\x03': return 'CTRL_C'   # Ctrl+C
    elif key == b'\x1b': return 'ESC'      # Esc
    
    return None

def terminal_file_selector(base_dir=".", extensions=None):
    """
    Interactive TUI file explorer.
    Navigation: Up/Down Arrows
    Selection: Space
    Enter Dir: Enter / Right
    Up Dir: Backspace / Left (on ..)
    Confirm: Enter on "DONE"
    """
    current_dir = os.path.abspath(base_dir)
    selected_files = [] # Set of absolute paths
    cursor_idx = 0
    msg = ""

    while True:
        # 1. Prepare Content
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
        
        # Build menu items
        # Structure: (Type, Name, DisplayText, Path/None)
        items = []
        
        # Add "Go Up" option if not at base (or just always allow it if user wants to traverse up)
        # To respect base_dir constraint, we might check, but typically flexibility is better.
        # Let's check if current dir is base dir to hide ".." if desired, OR just always show it.
        # User requested "Navigatable", so traversing up is good.
        if os.path.dirname(current_dir) != current_dir: # Not at root
             items.append(("UP", "..", "[..] Go Up", os.path.dirname(current_dir)))
             
        for d in dirs:
            items.append(("DIR", d, f"[{d}]", os.path.join(current_dir, d)))
            
        for f in files:
            fpath = os.path.join(current_dir, f)
            is_selected = fpath in selected_files
            mark = "[*]" if is_selected else "[ ]"
            items.append(("FILE", f, f"{mark} {f}", fpath))
            
        # Add DONE at the top or bottom? Often bottom is intuitive, but if list is long...
        # Let's put DONE at the very top for quick access if selection is done, 
        # or bottom. Let's stick to bottom as per previous request logic index 0.
        # Actually in TUI list, scrolling to bottom is annoying. 
        # Let's stick "DONE" as a special item at position 0? Or just press a specific key?
        # Let's add [DONE] at the top.
        
        HEADER_ITEMS = [
            ("DONE", "Done", ">> FINISH SELECTION <<", None)
        ]
        
        full_options = HEADER_ITEMS + items
        
        # Clamp cursor
        if cursor_idx >= len(full_options):
            cursor_idx = len(full_options) - 1
        if cursor_idx < 0:
            cursor_idx = 0
            
        # 2. Render
        clear_screen()
        print(f"--- File Explorer: {current_dir} ---")
        if msg:
            print(f"   > {msg}")
            msg = "" # consume message
            
        print(f"Selected: {len(selected_files)} files")
        print("Controls: [Up/Down] Move | [Space] Select/Deselect | [Enter] Enter Dir/Confirm | [Backspace] Go Up")
        print("-" * 50)
        
        # Render Window (if too many files, we should slice)
        # Simple slicing for now
        MAX_H = 20
        start_slice = max(0, cursor_idx - MAX_H // 2)
        end_slice = min(len(full_options), start_slice + MAX_H)
        
        for i in range(start_slice, end_slice):
            opt = full_options[i]
            prefix = " > " if i == cursor_idx else "   "
            print(f"{prefix}{opt[2]}")
            
        if end_slice < len(full_options):
            print("   ... (more items) ...")

        # 3. Input
        action = get_key()
        
        if action == 'UP':
            cursor_idx = max(0, cursor_idx - 1)
        elif action == 'DOWN':
            cursor_idx = min(len(full_options) - 1, cursor_idx + 1)
        elif action == 'SPACE':
            current_opt = full_options[cursor_idx]
            if current_opt[0] == 'FILE':
                fpath = current_opt[3]
                if fpath in selected_files:
                    selected_files.remove(fpath)
                    msg = "Deselected."
                else:
                    selected_files.append(fpath)
                    msg = "Selected."
            elif current_opt[0] == 'DONE':
                return selected_files
        elif action == 'ENTER':
            current_opt = full_options[cursor_idx]
            if current_opt[0] == 'DIR' or current_opt[0] == 'UP':
                current_dir = current_opt[3]
                cursor_idx = 0 # Reset cursor on dir change
            elif current_opt[0] == 'DONE':
                return selected_files
            elif current_opt[0] == 'FILE':
                # Optional: Toggle on Enter too? Usually enter launches/opens, but here effectively toggles or does nothing.
                # Let's just toggle to be friendly.
                fpath = current_opt[3]
                if fpath in selected_files:
                    selected_files.remove(fpath)
                else:
                    selected_files.append(fpath)
        elif action == 'BACKSPACE' or action == 'LEFT':
             # Try to go up
             parent = os.path.dirname(current_dir)
             if parent != current_dir:
                 current_dir = parent
                 cursor_idx = 0
        elif action == 'CTRL_C':
            print("\nCancelled.")
            sys.exit(0) # Or return empty? Better to exit logic flow if user wants out.
            
    return selected_files

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
                # Try to parse line by line
                # Format guess: IP | Status | Ping OR just IP 
                 for line in f:
                    line = line.strip()
                    if not line: continue
                    parts = line.split('|')
                    # Flexible parsing attempt
                    entry = {"ip": parts[0].strip()}
                    if len(parts) > 1:
                        # try to find status and ping
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
