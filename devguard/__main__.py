import os
import sys
import re
import math
import fnmatch
import yaml
from datetime import datetime
import json
import platform
import argparse
import json
import platform
import hashlib

# Built-in baseline enterprise signatures
SECRET_PATTERNS = {
    # Matches the pure 20-character AWS Access Key ID starting with AKIA/ASIA anywhere
    "AWS Access Key ID": r"\b(AKIA|ASIA)[A-Z0-9]{16}\b",
    
    # Matches a standard 40-character AWS Secret Access Key string
    "AWS Secret Access Key": r"\b[A-Za-z0-9+/]{40}\b",
    
    # Matches Google API keys starting with AIza followed by 35 alphanumeric/dash characters
    "Google API Key": r"\bAIza[0-9A-Za-z-_]{35}\b",
    
    # Matches standard three-part JWT tokens starting with eyJ anywhere on the line
    "JSON Web Token (JWT)": r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    
    # Matches Slack incoming webhooks cleanly
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9_]{8}/B[A-Z0-9_]{8}/[A-Za-z0-9_]{24}",
    
    # Matches Stripe Live secret keys (sk_live_ followed by 24 or more alphanumeric characters)
    "Stripe Secret Key": r"\bsk_live_[A-Za-z0-9]{24,}\b",
    
    # Generic Private Key Block Header
    "Generic Private Key Header": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"
}
ENTROPY_THRESHOLD = 4.0

def calculate_entropy(text):
    if not text:
        return 0
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 2)


def init_project():
    """Automates project immunization by generating policy configs and injecting the pre-push hook script"""
    print("[INFO] Initializing DevGuard Enterprise Security Client...")

    if not os.path.exists(".git"):
        print("[ERROR] Target directory is not a valid Git repository. Run 'git init' first.")
        sys.exit(1)

    # 1. Create baseline configuration file safely
    policy_file = ".devguard.yml"
    if not os.path.exists(policy_file):
        default_yaml = """# DevGuard Team Compliance Policy Configuration
# Adjust global thresholds and append company-specific regex constraints below.

entropy_threshold: 4.0

custom_patterns:
  "Company Employee Token": "EMP-[0-9]{5}"
  "Internal Database String": "db_conn_string:[A-Za-z0-9]+"
"""
        with open(policy_file, "w", encoding="utf-8") as f:
            f.write(default_yaml)
        print("[SUCCESS] Created default policy file: .devguard.yml")

    # 2. Dynamically inject the pre-push hook file directly
    hooks_dir = os.path.join(".git", "hooks")
    os.makedirs(hooks_dir, exist_ok=True) 
    destination_hook = os.path.join(hooks_dir, "pre-push")

    # This shell script fires before code leaves the local machine
    hook_script_content = """#!/bin/sh
# DevGuard Active Defense Hook Wrapper

echo "[INFO] DevGuard executing automated pre-push security compliance audit..."

# Execute the global scanner wrapper
devguard scan

# Capture the exit status of the scanner
SCAN_EXIT_CODE=$?

if [ $SCAN_EXIT_CODE -ne 0 ]; then
    echo "[CRITICAL] Push blocked! DevGuard detected security liabilities in local files."
    exit 1
fi

echo "[SUCCESS] Security checks passed. Proceeding with push."
exit 0
"""

    try:
        with open(destination_hook, "w", newline='\n', encoding="utf-8") as h:
            h.write(hook_script_content)
        
        # Grant execution permissions (critical for macOS/Linux environments)
        try:
            os.chmod(destination_hook, 0o755)
        except:
            pass
            
        print("[SUCCESS] DevGuard active-defense hook successfully injected into .git system runtime.")
    except Exception as e:
        print(f"[ERROR] Failed to write active-defense hook script: {str(e)}")

def run_manual_scan(target_path=".", min_severity="LOW"):
    """Crawls a targeted directory or single file for leaks, enforcing dynamic context constraints"""
    SEVERITY_WEIGHTS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    target_min_weight = SEVERITY_WEIGHTS.get(min_severity.upper(), 1)

    print(f"[INFO] Running deep manual workspace scan at: {target_path} (Minimum Severity: {min_severity})")
    
    global ENTROPY_THRESHOLD
    policy_path = os.path.join(target_path, ".devguard.yml") if os.path.isdir(target_path) else ".devguard.yml"
    ignored_hashes = set()
    if os.path.exists(policy_path):
        with open(policy_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            if config and "entropy_threshold" in config:
                ENTROPY_THRESHOLD = float(config["entropy_threshold"])
            if config and "custom_patterns" in config:
                for name, pattern in config["custom_patterns"].items():
                    SECRET_PATTERNS[name] = pattern
            if "allowlist" in config and isinstance(config["allowlist"], list):
                ignored_hashes = set(config["allowlist"])        

    system_name = platform.node()
    operating_system = platform.system()
    timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    global_exclusions = {".git", "devguard-audit.json", "devguard-audit.log"}
    MEDIA_EXTENSIONS = {'.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4'}
    
    folder_ignore_rules = {}
    detailed_log_entries = []
    structured_violations = []
    violations_count = 0
    
    # Bumped minimum floor to 12 chars to block minified JS variables from entropy checks
    string_literal_pattern = r"['\"]([A-Za-z0-9_\-\#\!\@\$\%\^\&\*\(\)\+]{12,})['\"]"

    # FIRST PASS: Index active .gitignore constraints safely
    if os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            path_parts = os.path.normpath(root).split(os.sep)
            if any(part in global_exclusions for part in path_parts):
                continue

            if ".gitignore" in files:
                current_rules = set()
                git_ignore_path = os.path.join(root, ".gitignore")
                try:
                    with open(git_ignore_path, "r", encoding="utf-8") as g:
                        for line in g:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                clean_pattern = line.strip("/")
                                if clean_pattern:
                                    current_rules.add(clean_pattern)
                except:
                    pass
                if current_rules:
                    folder_ignore_rules[os.path.abspath(root)] = current_rules
    else:
        parent_dir = os.path.dirname(os.path.abspath(target_path))
        git_ignore_path = os.path.join(parent_dir, ".gitignore")
        if os.path.exists(git_ignore_path):
            current_rules = set()
            try:
                with open(git_ignore_path, "r", encoding="utf-8") as g:
                    for line in g:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            clean_pattern = line.strip("/")
                            if clean_pattern:
                                current_rules.add(clean_pattern)
            except:
                pass
            if current_rules:
                folder_ignore_rules[parent_dir] = current_rules

    # SECOND PASS: Context-aware security analysis loop (File vs Folder Routing)
    files_to_scan = []
    if os.path.isfile(target_path):
        files_to_scan = [(os.path.dirname(os.path.abspath(target_path)), [], [os.path.basename(target_path)])]
    else:
        files_to_scan = os.walk(target_path)

    for root, dirs, files in files_to_scan:
        path_parts = os.path.normpath(root).split(os.sep)
        if any(part in global_exclusions for part in path_parts):
            continue

        should_skip_dir = False
        current_abs_path = os.path.abspath(root)
        for rule_root_path, patterns in folder_ignore_rules.items():
            if current_abs_path == rule_root_path or current_abs_path.startswith(rule_root_path + os.sep):
                rel_sub_path = os.path.relpath(current_abs_path, rule_root_path)
                rel_parts = rel_sub_path.split(os.sep) if rel_sub_path != "." else []
                if any(any(fnmatch.fnmatch(part, pattern) for pattern in patterns) for part in rel_parts):
                    should_skip_dir = True
                    break
        if should_skip_dir:
            continue

        for file in files:
            PRODUCTION_EXCLUSIONS = {
                "cli.py", "pre-push", ".devguard.yml", ".gitignore", 
                "package-lock.json", "package.json", "yarn.lock", "pnpm-lock.yaml"
            }
            file_ext = os.path.splitext(file)[1].lower()
            if file in PRODUCTION_EXCLUSIONS or file.endswith(".js.map") or file_ext in MEDIA_EXTENSIONS:
                continue 
                
            file_path = os.path.join(root, file)

            try:
                with open(file_path, "rb") as binary_check:
                    chunk = binary_check.read(1024)
                    if b'\x00' in chunk:
                        continue
            except (OSError, IOError):
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    flagged_lines = set()
                    for line_num, line in enumerate(f, 1):
                        flagged_by_regex = False
                        
                        # 1. Signature Regular Expression Matches
                        for rule_name, pattern in SECRET_PATTERNS.items():
                            match = re.search(pattern, line, re.IGNORECASE if "jwt" in rule_name else 0)
                            if match:
                                matched_secret = match.group(0)
                                
                                # --- DUAL ENTROPY & CONTEXT GUARDRAILS ---
                                # Gate generic 40-character AWS Secret shapes
                                if rule_name == "AWS Secret Access Key":
                                    # Verification A: Chaos Threshold Check (~4.5+ for real base64)
                                    if calculate_entropy(matched_secret) < 4.5:
                                        continue
                                    
                                    # Verification B: Proximity Context Keyword Anchor
                                    if not re.search(r'aws|secret|key|id', line, re.IGNORECASE):
                                        continue

                                # Ignore standard code placeholder keywords
                                if any(pld in matched_secret.lower() for pld in ["your_password_here", "insert_your", "placeholder"]):
                                    continue
                                # -----------------------------------------

                                item_severity = "HIGH"
                                if SEVERITY_WEIGHTS[item_severity] >= target_min_weight:
                                    detailed_msg = f"[LEAK DETECTED][HIGH] {file_path} [Line {line_num}] -> Rule: {rule_name}"
                                    print(detailed_msg)
                                    detailed_log_entries.append(detailed_msg)
                                    violations_count += 1
                                    
                                structured_violations.append({
                                    "file": file_path, "line": line_num, "type": "signature_violation",
                                    "rule": rule_name, "severity": item_severity
                                })
                                flagged_by_regex = True
                                flagged_lines.add(line_num)
                        
                        # 2. Secondary Randomness Entropy Loop
                        if line_num not in flagged_lines:
                            matches = re.findall(string_literal_pattern, line)
                            for token in matches:
                                score = calculate_entropy(token)
                                if score >= ENTROPY_THRESHOLD and not flagged_by_regex:
                                    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
                                    
                                    if token_hash in ignored_hashes:
                                        continue
                                        
                                    item_severity = "HIGH" if score >= 5.5 else ("MEDIUM" if score >= 4.5 else "LOW")
                                    
                                    if SEVERITY_WEIGHTS[item_severity] >= target_min_weight:
                                        detailed_msg = f"[SUSPICIOUS STRING][{item_severity}] {file_path} [Line {line_num}] -> Score: {score} (Hash: {token_hash})"
                                        print(detailed_msg)
                                        detailed_log_entries.append(detailed_msg)
                                        violations_count += 1
                                        
                                    structured_violations.append({
                                        "file": file_path, "line": line_num, "type": "high_entropy",
                                        "score": score, "severity": item_severity, "hash": token_hash
                                    })
                                    break
            except Exception as file_read_error:
                pass

    # Write output logs directly
    log_file_path = os.path.join(target_path, "devguard-audit.log") if os.path.isdir(target_path) else "devguard-audit.log"
    report_file_path = os.path.join(target_path, "devguard-audit.json") if os.path.isdir(target_path) else "devguard-audit.json"
    
    try:
        with open(log_file_path, "w", encoding="utf-8") as log_file:
            log_file.write(f"DevGuard Internal Troubleshooting Log\nTimestamp: {timestamp_str}\nEnvironment: {system_name}\nTotal Visible Blocked Violations: {violations_count}\n" + "="*70 + "\n\n")
            for entry in detailed_log_entries:
                log_file.write(entry + "\n")
        print(f"[INFO] Diagnostics log generated at: {log_file_path}")
    except:
        pass

    report_data = {
        "report_meta": {"client": "DevGuard Security Enterprise", "execution_timestamp": timestamp_str, "origin_system_id": system_name, "platform_environment": operating_system, "scanned_path": os.path.abspath(target_path)},
        "compliance_summary": {"status": "COMPLIANT" if violations_count == 0 else "NON_COMPLIANT", "total_liabilities_detected": violations_count}
    }
    try:
        with open(report_file_path, "w", encoding="utf-8") as report_file:
            json.dump(report_data, report_file, indent=2)
        print(f"[INFO] High-level compliance report generated at: {report_file_path}")
    except:
        pass

    if violations_count == 0:
        print("\n[SUCCESS] Workspace clean! No filtered policy or signature violations identified.")
        sys.exit(0)
    else:
        print(f"\n[ALERT] Scan completed. Found {violations_count} filtered security liabilities inside target area.")
        sys.exit(1)

def ignore_finding(target_hash):
    """Appends a safe finding signature hash directly to the local .devguard.yml exclusion allowlist without losing layout comments"""
    policy_file = ".devguard.yml"
    
    if not os.path.exists(policy_file):
        print("[ERROR] No configuration policy file (.devguard.yml) found. Run 'devguard init' first.")
        sys.exit(1)
        
    try:
        # Step 1: Read the file line-by-line to find duplicates or structure parameters
        with open(policy_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Clean check for duplicates
        if any(f"- {target_hash}" in line for line in lines):
            print(f"[INFO] Hash target sequence '{target_hash}' is already explicitly registered in the allowlist.")
            return

        allowlist_index = -1
        for idx, line in enumerate(lines):
            if line.strip().startswith("allowlist:"):
                allowlist_index = idx
                break

        # Step 2: In-place array injection logic
        if allowlist_index != -1:
            # If allowlist exists, inject the item right below the header
            lines.insert(allowlist_index + 1, f"  - {target_hash}\n")
        else:
            # If allowlist block is missing, append it beautifully at the bottom with comments
            lines.append("\n# Cryptographic signature hashes to bypass (False Positive Allowlist)\n")
            lines.append("allowlist:\n")
            lines.append(f"  - {target_hash}\n")

        # Step 3: Stream updates back to the file cleanly
        with open(policy_file, "w", encoding="utf-8") as f:
            f.writelines(lines)
            
        print(f"[SUCCESS] Successfully appended threat fingerprint '{target_hash}' to local compliance allowlist.")
    except Exception as e:
        print(f"[ERROR] Failed updating policy configurations cleanly: {str(e)}")
        sys.exit(1)


def get_system_status():
    """Extracts deployment verification metrics, file presence, and historical scan metadata records"""
    print("[INFO] Reviewing local runtime integrity matrices...")
    print("-" * 60)
    
    # 1. Check Configuration Presence
    config_exists = os.path.exists(".devguard.yml")
    print(f"Baseline Configuration Policy (.devguard.yml): {'[ FOUND ]' if config_exists else '[ MISSING ]'}")
    
    # 2. Check Git Hook Deployment Integrity
    hook_path = os.path.join(".git", "hooks", "pre-push")
    hook_installed = os.path.exists(hook_path)
    print(f"Active Defense Hook Injection (pre-push):   {'[ DEPLOYED ]' if hook_installed else '[ NOT INSTALLED ]'}")
    
    # 3. Read Last Scan Records from telemetry audit cache
    report_path = "devguard-audit.json"
    if os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as r:
                data = json.load(r)
                meta = data.get("report_meta", {})
                summary = data.get("compliance_summary", {})
                
                print(f"Last Security Audit Timestamp:              {meta.get('execution_timestamp', 'UNKNOWN')}")
                print(f"Last Reported Compliance Status:           [ {summary.get('status', 'UNKNOWN')} ]")
                print(f"Last Logged Structural Liabilities:        {summary.get('total_liabilities_detected', 0)}")
        except:
            print("Audit Report Cache Status:                  [ CORRUPTED ]")
    else:
        print("Historical Audit Logs:                      [ NO PAST SCANS REGISTERED ]")
    print("-" * 60)        

def main():
    """Advanced CLI argument router processing execution parameters for DevGuard"""
    parser = argparse.ArgumentParser(
        description="DevGuard Enterprise Security Client: Context-aware secrets scanning utility."
    )
    subparsers = parser.add_subparsers(dest="command", help="Execution command profiles")
    
    subparsers.add_parser("init", help="Inject active-defense pre-push hook configuration properties")
    
    scan_parser = subparsers.add_parser("scan", help="Execute deep repository analysis operations")
    
    # CHANGED: Made path a positional argument so you can just type: devguard scan "file.py"
    # Set nargs="?" so it's optional and defaults to "." if you just type: devguard scan
    scan_parser.add_argument("path", type=str, nargs="?", default=".", help="Target file or subdirectory path")
    
    # Alternatively, if you want it to be a flag named --file, uncomment the line below:
    # scan_parser.add_argument("--file", type=str, dest="path", default=".", help="Target file path")

    scan_parser.add_argument("--severity", type=str, default="LOW", choices=["LOW", "MEDIUM", "HIGH"], help="Severity tier filter threshold")
    
    ignore_parser = subparsers.add_parser("ignore", help="Append specific threat asset hashes to policy exclusion map")
    ignore_parser.add_argument("hash", type=str, help="Target SHA-256 validation signature value to bypass")
    
    subparsers.add_parser("status", help="Display core environment properties and hook deployment state verification matrices")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "init":
        init_project()
    elif args.command == "scan":
        # Maps args.path directly into your existing scanner handler
        run_manual_scan(target_path=args.path, min_severity=args.severity)
    elif args.command == "ignore":
        ignore_finding(args.hash)
    elif args.command == "status":
        get_system_status()


if __name__ == "__main__":
    main()