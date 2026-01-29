import json
import os
import subprocess
import sys
import time

# =============================================================================
# Chain #20 IDE Simulator
# Simulates VS Code startup and extension behavior.
# It reads .vscode/settings.json and blindly executes configured paths.
# =============================================================================

WORKING_DIR = "workspace_project"
SETTINGS_PATH = os.path.join(WORKING_DIR, ".vscode/settings.json")

def simulate_ide_startup():
    print("==================================================================")
    print("   Chain #20: Fake IDE (VS Code Simulator)                        ")
    print("==================================================================\n")
    print(f"[*] Opening workspace: {os.path.abspath(WORKING_DIR)}")

    if not os.path.exists(SETTINGS_PATH):
        print(f"[!] No config found at {SETTINGS_PATH}")
        print("    Run 'config_victim_agent.py' first to generate malicious config.")
        return

    print(f"[*] Found workspace settings: {SETTINGS_PATH}")
    
    try:
        with open(SETTINGS_PATH, 'r') as f:
            settings = json.load(f)
        
        # Simulate the PHP Extension reacting to configuration
        # Target setting: php.validate.executablePath
        validator_path = settings.get("php.validate.executablePath")
        
        if validator_path:
            print(f"[*] PHP Extension loaded.")
            print(f"[*] Found custom validator configuration: '{validator_path}'")
            print("[*] Validating project files...")
            
            # Resolve path relative to workspace
            exec_path = os.path.join(WORKING_DIR, validator_path)
            
            if os.path.exists(exec_path):
                print(f"[*] Executing validator binary: {exec_path}")
                print("-" * 50)
                
                # --- VULNERABILITY TRIGGER ---
                # The IDE executes the configure binary to perform "validation"
                try:
                    # In a real IDE, this happens in the background.
                    # Here we capture output to show success.
                    result = subprocess.run([exec_path], capture_output=True, text=True, timeout=5)
                    
                    print(">>> STDOUT:")
                    print(result.stdout)
                    
                    if result.stderr:
                        print(">>> STDERR:")
                        print(result.stderr)
                        
                    if "RCE SUCCESSFUL" in result.stdout:
                         print("\n[!!!] RCE DETECTED [!!!]")
                         print("The malicious script configured in settings.json was executed successfully.")
                         print("In a real attack, this script could silence itself and install a backdoor.")
                except subprocess.TimeoutExpired:
                    print("[!] Execution timed out.")
                except Exception as e:
                    print(f"[!] Execution failed: {e}")
            else:
                print(f"[!] Configured executable not found on disk: {exec_path}")
        else:
            print("[*] 'php.validate.executablePath' not set. Safe.")

    except json.JSONDecodeError:
        print("[!] Settings file contains invalid JSON.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    simulate_ide_startup()
