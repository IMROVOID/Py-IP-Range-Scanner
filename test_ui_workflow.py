import sys
import os
import unittest
from unittest.mock import MagicMock, patch
import io

# Add project dir to sys.path
sys.path.append(os.getcwd())

import main

class TestWorkflow(unittest.TestCase):
    
    @patch('builtins.print')
    @patch('builtins.input')
    @patch('main.terminal_menu')
    @patch('time.sleep')
    def test_workflow_generate_cloudflare(self, mock_sleep, mock_menu, mock_input, mock_print):
        print("Testing: Generate Cloudflare Ranges")
        
        # Define menu behavior based on Title
        def side_effect_menu(options, title=None):
            if "Py IP Range Scanner" in str(title): return 0 # Scan IP Ranges
            if "Generate & Scan IP Ranges" in str(title): return 0 # Templates
            if "Select Template" in str(title): return 0 # Cloudflare
            if "Scan Generated Ranges" in str(title): return 1 # Return to Menu (Don't scan in this test)
            return -1 # Default back
            
        mock_menu.side_effect = side_effect_menu
        mock_input.side_effect = ["", ""] # Press Enter to continue
        
        # Logic to exit loop: We need to raise an exception or mock main_menu to return
        # Since main_menu loop is infinite, we can't easily test "main_menu" directly unless we mock it to run once.
        # Instead, we test 'menu_scan_ip_ranges' logic.
        
        cfg = main.ConfigManager()
        tester = main.IPTester(cfg)
        gen = main.IPGenerator(tester)
        
        # Run
        main.menu_scan_ip_ranges(cfg, tester, gen)
        
        # Verify
        # Check if files generated
        files = os.listdir(main.OUTPUT_RANGES_DIR)
        cloudflare_files = [f for f in files if "CloudFlare" in f]
        self.assertTrue(len(cloudflare_files) > 0, "No Cloudflare files generated")
        print(f"Generated {len(cloudflare_files)} Cloudflare files.")

    @patch('builtins.print')
    @patch('builtins.input')
    @patch('main.terminal_menu')
    @patch('time.sleep')
    def test_scan_ips_interactive(self, mock_sleep, mock_menu, mock_input, mock_print):
        print("\nTesting: Scan IPs Interactive (Small Batch)")
        
        def side_effect_menu(options, title=None):
            if "Scan IPs" in str(title): return 0 # Terminal Input
            return -1
            
        mock_menu.side_effect = side_effect_menu
        # Inputs: IP, Save? (n)
        mock_input.side_effect = ["8.8.8.8, 1.1.1.1", "n"] 
        
        cfg = main.ConfigManager()
        tester = main.IPTester(cfg)
        
        # Run
        main.menu_scan_ips(cfg, tester)
        
        # Verify
        # We can check if "Results discarded" was printed
        # mock_print is called many times.
        # Let's check call args
        found = False
        for call in mock_print.call_args_list:
            if "Results discarded" in str(call):
                found = True
                break
        self.assertTrue(found, "Results should be discarded")

    @patch('builtins.print')
    @patch('builtins.input')
    @patch('main.terminal_menu')
    @patch('time.sleep')
    def test_settings_combobox(self, mock_sleep, mock_menu, mock_input, mock_print):
        print("\nTesting: Settings ComboBox")
        
        # Goal: Change Port to 8080
        def side_effect_menu(options, title=None):
            if "Global Settings" in str(title): 
                # Find index of 'port'
                # Options are tuples (key, disp). We need to find index.
                # In test we assume we know index or search.
                # 'options' passed to mock is list of tuples.
                for i, opt in enumerate(options):
                    if isinstance(opt, tuple) and opt[0] == 'port': return i
                return -1
            
            if "Select Port" in str(title):
                # options are [80, 443, 8080, ...]
                # 8080 is usually index 2 (if 80, 443, 8080...)
                # Let's return 2
                return 2
                
            return -1
            
        mock_menu.side_effect = side_effect_menu
        
        cfg = main.ConfigManager()
        
        # Run
        # We need to break the infinite loop in menu_settings
        # We can throw StopIteration after first run or something?
        # Or mock terminal_menu to return -1 on second call.
        
        # Complex side effect for menu to exit loop
        self.menu_calls = 0
        def side_effect_loop(options, title=None):
            self.menu_calls += 1
            if "Global Settings" in str(title):
                if self.menu_calls == 1:
                     # Find port
                     for i, opt in enumerate(options):
                        if isinstance(opt, tuple) and opt[0] == 'port': return i
                return -1 # Exit
            if "Select Port" in str(title): return 2 # 8080
            return -1
            
        mock_menu.side_effect = side_effect_loop
        
        main.menu_settings(cfg)
        
        # Verify
        defaults = cfg.get_defaults()
        self.assertEqual(defaults['port'], 8080)
        print("Port updated to 8080 successfully.")

if __name__ == '__main__':
    unittest.main()
