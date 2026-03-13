import json
import subprocess
import sys
import base64
import os

# =============================================================================
# Chain #8 Victim Agent Simulator
# Vulnerable Shell Execution via ASCII Smuggling
# =============================================================================

class MaliciousToolExecutor:
    def execute_shell(self, command: str):
        """
        Vulnerable shell executor that lacks sophisticated content filtering.
        
        Args:
            command (str): The shell command to execute.
        """
        print(f"\n[*] [Alert] Executor received command: {command}")
        
        # Simple/Weak Static Filter Simulation
        # This filter mimics a naive defense that only blocks obvious keywords
        blacklisted_keywords = ["curl", "wget", "nc", "bash -i", "/dev/tcp"]
        for keyword in blacklisted_keywords:
            if keyword in command and "base64" not in command: # Simulate bypass logic flaw
                print(f"[!] Blocked by Static Filter: Found keyword '{keyword}'")
                return "Error: Command blocked by security policy."
        
        print(f"[*] Command passed static filter check.")
        print("-" * 40)
        
        try:
            # VULNERABILITY: shell=True allows complex pipelines like "echo ... | base64 -d | bash"
            if sys.platform.startswith('win'):
                # Windows adjustment for demo purposes (base64 might not be available by default in cmd)
                # But the concept is the same (powershell -EncodedCommand etc)
                print("[!] Warning: Running on Windows, 'base64' command might fail unless in WSL/Git Bash.")
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            else:
                # Unix/Linux environment
                # The critical vulnerability is enabling shell pipelines for user input
                output = subprocess.check_output(command, shell=True, executable='/bin/bash', stderr=subprocess.STDOUT)
                
            result = output.decode('utf-8', errors='replace')
            print("Command Output:")
            print(result)
            return result
            
        except subprocess.CalledProcessError as e:
            error_msg = e.output.decode('utf-8', errors='replace')
            print("Command Failed:")
            print(error_msg)
            return f"Error: {error_msg}"
        except Exception as e:
            print(f"Execution Error: {e}")
            return f"Error: {str(e)}"

def main():
    print("==================================================================")
    print("   Chain #8: ASCII Smuggling EchoLeak Simulation                  ")
    print("==================================================================\n")
    
    print("This script simulates an Agent with a 'execute_shell' tool.")
    print("The goal is to bypass the static filter using Base64 ASCII smuggling.")
    print("Try injecting this payload (Base64 for 'id'):")
    print("  echo aWQ= | base64 -d | bash")
    print("-" * 60)
    
    executor = MaliciousToolExecutor()
    
    try:
        user_input_str = input("Paste JSON Tool Call here (e.g. {\"tool\": \"execute_shell\", \"parameters\": {\"command\": \"...\"}}): ").strip()
        
        # Allow raw command input for convenience if not JSON
        if not user_input_str.startswith("{"):
             # Assume it's just the raw command for testing
             executor.execute_shell(user_input_str)
             return

        data = json.loads(user_input_str)
        tool_name = data.get("tool")
        params = data.get("parameters", {})
        
        if tool_name == "execute_shell":
            cmd = params.get("command")
            if cmd:
                executor.execute_shell(cmd)
            else:
                print("Error: Missing 'command' parameter.")
        else:
            print(f"Unknown tool: {tool_name}")
            
    except json.JSONDecodeError:
        print("Invalid JSON format.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
