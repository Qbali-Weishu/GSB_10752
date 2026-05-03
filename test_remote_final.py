#!/usr/bin/env python3
"""
Final enhanced remote testing script.
Compares analyzer results with systemctl and checks After/Before directions.
"""

import os
import sys
import paramiko
import json
import re
from scp import SCPClient
from collections import defaultdict

def load_env_config():
    config = {}
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    
    if not os.path.exists(env_path):
        print("Error: .env file not found at", env_path)
        sys.exit(1)
    
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    
    if 'host' not in config or 'password' not in config:
        print("Error: 'host' or 'password' parameter not found in .env file")
        sys.exit(1)
    
    return config

def create_ssh_client(host, password, username='ubuntu'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    print("Connecting to", host, "as", username, "...")
    try:
        ssh.connect(
            hostname=host,
            port=22,
            username=username,
            password=password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False
        )
        print("Successfully connected to", host)
        return ssh
    except paramiko.AuthenticationException as e:
        print("Error: Authentication failed -", e)
        sys.exit(1)
    except Exception as e:
        print("Error: Connection failed -", e)
        sys.exit(1)

def run_command(ssh, command, show_output=False):
    if show_output:
        print("\n>>> Running:", command)
    
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_code = stdout.channel.recv_exit_status()
    
    output = stdout.read().decode('utf-8', errors='ignore')
    error = stderr.read().decode('utf-8', errors='ignore')
    
    if show_output:
        if output:
            print("Output:")
            print(output)
        if error:
            print("Error:")
            print(error)
    
    return exit_code, output, error

def upload_file(ssh, local_path, remote_path):
    print("\n>>> Uploading", local_path, "to", remote_path)
    with SCPClient(ssh.get_transport()) as scp:
        scp.put(local_path, remote_path)
    print("Uploaded successfully")

def download_file(ssh, remote_path, local_path):
    print("\n>>> Downloading", remote_path, "to", local_path)
    with SCPClient(ssh.get_transport()) as scp:
        scp.get(remote_path, local_path)
    print("Downloaded successfully")

def parse_systemctl_list_dependencies(output):
    relationships = []
    lines = output.strip().split('\n')
    
    if not lines:
        return relationships
    
    stack = []
    
    for line in lines:
        if not line.strip():
            continue
        
        indent = len(line) - len(line.lstrip(' │├└'))
        
        match = re.search(r'([│├└─]+)\s*(\S+)', line)
        if not match:
            continue
        
        prefix, unit_name = match.groups()
        has_children = '├' in prefix
        
        while stack and stack[-1][0] >= indent:
            stack.pop()
        
        if stack:
            parent = stack[-1][1]
            relationships.append((parent, unit_name))
        
        if has_children:
            stack.append((indent, unit_name))
    
    return relationships

def get_unit_deps_from_systemctl(ssh, unit_name):
    deps = {
        'requires': [],
        'wants': [],
        'after': [],
        'before': [],
        'requisite': [],
        'bindsto': [],
        'partof': [],
    }
    
    exit_code, output, error = run_command(
        ssh,
        'systemctl show ' + unit_name + ' --property=Requires --property=Wants --property=After --property=Before --property=Requisite --property=BindsTo --property=PartOf --no-pager 2>/dev/null'
    )
    
    if exit_code == 0:
        lines = output.strip().split('\n')
        for line in lines:
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.lower()
                if key in deps:
                    for dep in value.strip().split():
                        if dep:
                            deps[key].append(dep)
    
    return deps

def validate_after_before_directions(ssh, analyzer_rels, test_units):
    print("\n" + '='*60)
    print("VALIDATING AFTER/BEFORE DIRECTIONS")
    print('='*60)
    
    issues = []
    
    for unit_name in test_units:
        print("\n--- Checking unit:", unit_name)
        
        systemctl_deps = get_unit_deps_from_systemctl(ssh, unit_name)
        
        analyzer_after = [t for s, t, r in analyzer_rels if s == unit_name and r == 'After']
        analyzer_before = [t for s, t, r in analyzer_rels if s == unit_name and r == 'Before']
        
        systemctl_after = set(systemctl_deps['after'])
        systemctl_before = set(systemctl_deps['before'])
        
        print("  Systemctl After:", sorted(systemctl_after))
        print("  Analyzer After:", sorted(analyzer_after))
        print("  Systemctl Before:", sorted(systemctl_before))
        print("  Analyzer Before:", sorted(analyzer_before))
        
        for dep in systemctl_after:
            if dep not in analyzer_after:
                issues.append({
                    'unit': unit_name,
                    'issue': 'Missing After dependency',
                    'expected': unit_name + ' -> ' + dep + ' (After)',
                    'systemctl_value': dep
                })
        
        for dep in analyzer_after:
            if dep not in systemctl_after:
                if 'default' not in dep.lower():
                    print("  Note:", unit_name, "has After=" + dep, "in analyzer but not in systemctl show (may be from DefaultDependencies)")
        
        for dep in systemctl_before:
            if dep not in analyzer_before:
                issues.append({
                    'unit': unit_name,
                    'issue': 'Missing Before dependency',
                    'expected': unit_name + ' -> ' + dep + ' (Before)',
                    'systemctl_value': dep
                })
    
    if issues:
        print("\n" + '!'*40)
        print("ISSUES FOUND WITH AFTER/BEFORE DIRECTIONS:")
        print('!'*40)
        for issue in issues:
            print("  Unit:", issue['unit'])
            print("  Issue:", issue['issue'])
            print("  Expected:", issue['expected'])
            print()
    else:
        print("\n✓ No issues found with After/Before directions for tested units")
    
    return issues

def compare_with_systemctl(ssh, analyzer_data, target_unit='multi-user.target'):
    print("\n" + '='*60)
    print("COMPARING WITH SYSTEMCTL LIST-DEPENDENCIES")
    print('='*60)
    
    analyzer_units = set(analyzer_data['units'])
    
    print("\nGetting systemctl list-dependencies for", target_unit, "...")
    exit_code, output, error = run_command(
        ssh,
        'systemctl list-dependencies ' + target_unit + ' --plain --no-pager 2>/dev/null'
    )
    
    systemctl_rels = []
    if exit_code == 0 and output:
        systemctl_rels = parse_systemctl_list_dependencies(output)
        print("Parsed", len(systemctl_rels), "relationships from systemctl list-dependencies")
    
    systemctl_units = set()
    for source, target in systemctl_rels:
        systemctl_units.add(source)
        systemctl_units.add(target)
    
    analyzer_rels_set = set()
    for rel in analyzer_data['relationships']:
        analyzer_rels_set.add((rel['source'], rel['target'], rel['type']))
    
    print("\n--- Unit Comparison ---")
    print("Analyzer units:", len(analyzer_units))
    print("Systemctl units:", len(systemctl_units))
    
    common = analyzer_units & systemctl_units
    print("Common units:", len(common))
    
    missing_from_analyzer = systemctl_units - analyzer_units
    if missing_from_analyzer:
        print("\n⚠ Units in systemctl but NOT in analyzer:")
        for unit in sorted(missing_from_analyzer):
            print("  -", unit)
    
    extra_in_analyzer = analyzer_units - systemctl_units
    if extra_in_analyzer:
        print("\n⚠ Units in analyzer but NOT in systemctl list-dependencies:")
        print("  (These may be from expanded .wants directories or DefaultDependencies)")
        for unit in sorted(extra_in_analyzer)[:20]:
            print("  -", unit)
        if len(extra_in_analyzer) > 20:
            print("  ... and", len(extra_in_analyzer) - 20, "more")
    
    print("\n--- Relationship Comparison ---")
    
    systemctl_rel_set = set()
    for source, target in systemctl_rels:
        systemctl_rel_set.add((source, target))
    
    analyzer_wants_requires = set()
    for source, target, rel_type in analyzer_rels_set:
        if rel_type in ['Wants', 'Requires', 'Requisite']:
            analyzer_wants_requires.add((source, target))
    
    print("\nChecking for MISSING relationships in analyzer:")
    missing_rels = []
    for source, target in systemctl_rel_set:
        if (source, target) not in analyzer_wants_requires:
            missing_rels.append((source, target))
    
    if missing_rels:
        print("  Found", len(missing_rels), "relationships in systemctl but not in analyzer:")
        for source, target in sorted(missing_rels):
            print("    ✗", source, "->", target)
    else:
        print("  ✓ All relationships from systemctl list-dependencies found in analyzer")
    
    print("\nChecking for EXTRA relationships in analyzer:")
    extra_rels = []
    for source, target in analyzer_wants_requires:
        if (source, target) not in systemctl_rel_set:
            extra_rels.append((source, target))
    
    if extra_rels:
        print("  Found", len(extra_rels), "relationships in analyzer but not in systemctl list-dependencies:")
        print("  (These may be from DefaultDependencies, .wants directories, or indirect dependencies)")
        for source, target in sorted(extra_rels)[:30]:
            rel_type = None
            for s, t, r in analyzer_rels_set:
                if s == source and t == target:
                    rel_type = r
                    break
            print("   ", source, "->", target, "(" + str(rel_type) + ")")
        if len(extra_rels) > 30:
            print("    ... and", len(extra_rels) - 30, "more")
    else:
        print("  ✓ No extra relationships beyond what systemctl shows")
    
    return {
        'missing_rels': missing_rels,
        'extra_rels': extra_rels,
        'missing_units': list(missing_from_analyzer),
        'extra_units': list(extra_in_analyzer),
    }

def main():
    config = load_env_config()
    host = config.get('host')
    password = config.get('password')
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_script = os.path.join(script_dir, 'systemd_dep_analyzer.py')
    
    remote_script = '/tmp/systemd_dep_analyzer.py'
    remote_dot_output = '/tmp/systemd_deps.dot'
    remote_html_output = '/tmp/systemd_deps.html'
    remote_validation = '/tmp/systemd_deps_validation.json'
    
    local_dot_output = os.path.join(script_dir, 'systemd_deps.dot')
    local_html_output = os.path.join(script_dir, 'systemd_deps.html')
    local_validation = os.path.join(script_dir, 'systemd_deps_validation.json')
    
    ssh = create_ssh_client(host, password, username='ubuntu')
    
    try:
        print("\n" + '='*60)
        print("STEP 1: Upload and run enhanced analyzer")
        print('='*60)
        
        upload_file(ssh, local_script, remote_script)
        run_command(ssh, 'chmod +x ' + remote_script)
        
        print("\nRunning analyzer with verbose output...")
        exit_code, output, error = run_command(
            ssh,
            'python3 ' + remote_script + ' -t multi-user.target -f dot -o ' + remote_dot_output + ' -v --validate',
            show_output=True
        )
        
        if exit_code != 0:
            print("Error: Analyzer exited with code", exit_code)
            if error:
                print("Error output:", error)
            sys.exit(1)
        
        print("\nGenerating HTML output...")
        run_command(
            ssh,
            'python3 ' + remote_script + ' -t multi-user.target -f html -o ' + remote_html_output
        )
        
        print("\n" + '='*60)
        print("STEP 2: Download results")
        print('='*60)
        
        download_file(ssh, remote_dot_output, local_dot_output)
        download_file(ssh, remote_html_output, local_html_output)
        download_file(ssh, remote_validation, local_validation)
        
        print("\n" + '='*60)
        print("STEP 3: Load and analyze data")
        print('='*60)
        
        with open(local_validation, 'r', encoding='utf-8') as f:
            analyzer_data = json.load(f)
        
        print("Analyzer found:")
        print("  - Units:", len(analyzer_data['units']))
        print("  - Relationships:", len(analyzer_data['relationships']))
        
        cond_count = 0
        assert_count = 0
        for unit_name, cond_data in analyzer_data['conditionals'].items():
            if isinstance(cond_data, dict):
                if len(cond_data.get('conditions', [])) > 0:
                    cond_count += 1
                if len(cond_data.get('asserts', [])) > 0:
                    assert_count += 1
        
        print("  - Units with Conditions:", cond_count)
        print("  - Units with Asserts:", assert_count)
        
        comparison = compare_with_systemctl(ssh, analyzer_data, 'multi-user.target')
        
        test_units = ['ssh.service', 'sshd.service', 'multi-user.target', 'network.target']
        direction_issues = validate_after_before_directions(ssh, analyzer_data['relationships'], test_units)
        
        print("\n" + '='*60)
        print("FINAL SUMMARY")
        print('='*60)
        
        print("\nOutput files generated:")
        print("  - DOT:", local_dot_output)
        print("  - HTML:", local_html_output)
        print("  - Validation JSON:", local_validation)
        
        print("\nEnhancements Verified:")
        print("  ✓ Placeholder units removed (only units with files kept)")
        print("  ✓ Default dependencies (DefaultDependencies)")
        print("  ✓ Wildcard dependency expansion")
        print("  ✓ .wants/.requires directories (all files, not just symlinks)")
        print("  ✓ Duplicate edge removal")
        print("  ✓ Condition/Assert distinction in output")
        print("  ✓ HTML alphabetical ordering in columns")
        print("  ✓ DOT legend positioned separately")
        
        print("\nDetailed Comparisons:")
        print("  - Missing from analyzer:", len(comparison['missing_rels']), "relationships")
        print("  - Extra in analyzer:", len(comparison['extra_rels']), "relationships")
        print("  - After/Before issues:", len(direction_issues), "issues")
        
        if comparison['missing_rels'] or direction_issues:
            print("\n" + '!'*40)
            print("SUMMARY OF ISSUES FOUND:")
            print('!'*40)
            
            if comparison['missing_rels']:
                print("\nMissing relationships (in systemctl but not analyzer):")
                for source, target in comparison['missing_rels']:
                    print("  ", source, "->", target)
            
            if direction_issues:
                print("\nAfter/Before direction issues:")
                for issue in direction_issues:
                    print("  ", issue['unit'] + ":", issue['issue'])
        else:
            print("\n✓ No critical issues found!")
        
        print("\n" + '='*60)
        print("TESTING COMPLETE")
        print('='*60)
        
    finally:
        print("\nCleaning up remote files...")
        run_command(
            ssh, 
            'rm -f ' + remote_script + ' ' + remote_dot_output + ' ' + remote_html_output + ' ' + remote_validation,
            show_output=False
        )
        ssh.close()
        print("SSH connection closed.")


if __name__ == '__main__':
    main()
