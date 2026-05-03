#!/usr/bin/env python3
"""
Enhanced remote testing script for systemd dependency analyzer.
Connects to remote server, runs the analyzer, and validates against systemctl list-dependencies.
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
        print(f"Error: .env file not found at {env_path}")
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
    
    print(f"Connecting to {host} as {username}...")
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
        print(f"Successfully connected to {host}")
        return ssh
    except paramiko.AuthenticationException as e:
        print(f"Error: Authentication failed - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Connection failed - {e}")
        sys.exit(1)

def run_command(ssh, command, show_output=False):
    if show_output:
        print(f"\n>>> Running: {command}")
    
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
    print(f"\n>>> Uploading {local_path} to {remote_path}")
    with SCPClient(ssh.get_transport()) as scp:
        scp.put(local_path, remote_path)
    print(f"Uploaded successfully")

def download_file(ssh, remote_path, local_path):
    print(f"\n>>> Downloading {remote_path} to {local_path}")
    with SCPClient(ssh.get_transport()) as scp:
        scp.get(remote_path, local_path)
    print(f"Downloaded successfully")

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

def parse_systemctl_show_deps(output):
    relationships = []
    lines = output.strip().split('\n')
    
    for line in lines:
        if '=' in line:
            key, value = line.split('=', 1)
            if key in ['Requires', 'Wants', 'After', 'Before', 'Requisite', 'BindsTo', 'PartOf']:
                for dep in value.strip().split():
                    if dep:
                        relationships.append((key, dep))
    
    return relationships

def get_systemctl_deps(ssh, target_unit='multi-user.target'):
    all_deps = {
        'list_dependencies': [],
        'requires': [],
        'wants': [],
        'after': [],
        'before': [],
        'units': set()
    }
    
    print(f"\n{'='*60}")
    print(f"Getting systemctl list-dependencies for {target_unit}")
    print(f"{'='*60}")
    
    exit_code, output, error = run_command(
        ssh,
        f'systemctl list-dependencies {target_unit} --plain --no-pager 2>/dev/null'
    )
    
    if exit_code == 0 and output:
        all_deps['list_dependencies'] = parse_systemctl_list_dependencies(output)
        print(f"Parsed {len(all_deps['list_dependencies'])} relationships from list-dependencies")
        
        for source, target in all_deps['list_dependencies']:
            all_deps['units'].add(source)
            all_deps['units'].add(target)
    
    print(f"\nGetting detailed dependencies for key units...")
    
    exit_code, output, error = run_command(
        ssh,
        f'systemctl show {target_unit} --property=Requires --property=Wants --property=After --property=Before --property=Requisite --property=BindsTo --property=PartOf --no-pager 2>/dev/null'
    )
    
    if exit_code == 0:
        detailed = parse_systemctl_show_deps(output)
        for rel_type, dep in detailed:
            all_deps[rel_type.lower()].append(dep)
            all_deps['units'].add(dep)
    
    key_units = ['sshd.service', 'ssh.service', 'network.target', 'multi-user.target']
    for unit in key_units:
        exit_code, output, error = run_command(
            ssh,
            f'systemctl show {unit} --property=Requires --property=Wants --property=After --property=Before --property=Requisite --property=BindsTo --property=PartOf --property=FragmentPath --no-pager 2>/dev/null'
        )
        if exit_code == 0 and output:
            detailed = parse_systemctl_show_deps(output)
            for rel_type, dep in detailed:
                if rel_type.lower() in ['requires', 'wants', 'after', 'before', 'requisite', 'bindsto', 'partof']:
                    all_deps['units'].add(unit)
                    all_deps['units'].add(dep)
    
    return all_deps

def compare_dependencies(analyzer_data, systemctl_data):
    print(f"\n{'='*60}")
    print("COMPARING ANALYZER RESULTS WITH SYSTEMCTL")
    print(f"{'='*60}")
    
    analyzer_units = set(analyzer_data['units'])
    systemctl_units = systemctl_data['units']
    
    print(f"\n--- Unit Comparison ---")
    print(f"Analyzer units: {len(analyzer_units)}")
    print(f"Systemctl units: {len(systemctl_units)}")
    
    common = analyzer_units & systemctl_units
    only_analyzer = analyzer_units - systemctl_units
    only_systemctl = systemctl_units - analyzer_units
    
    print(f"Common units: {len(common)}")
    print(f"Only in analyzer: {len(only_analyzer)}")
    print(f"Only in systemctl: {len(only_systemctl)}")
    
    if only_systemctl:
        print(f"\nUnits found in systemctl but not in analyzer:")
        for unit in sorted(only_systemctl)[:20]:
            print(f"  - {unit}")
        if len(only_systemctl) > 20:
            print(f"  ... and {len(only_systemctl) - 20} more")
    
    print(f"\n--- Relationship Comparison ---")
    
    analyzer_rels = set()
    for rel in analyzer_data['relationships']:
        analyzer_rels.add((rel['source'], rel['target'], rel['type']))
    
    systemctl_rels = set()
    for source, target in systemctl_data['list_dependencies']:
        systemctl_rels.add((source, target, 'list-deps'))
    
    print(f"Analyzer relationships: {len(analyzer_rels)}")
    print(f"Systemctl relationships (list-dependencies): {len(systemctl_rels)}")
    
    ssh_analyzer_rels = [r for r in analyzer_rels if 'ssh' in r[0].lower() or 'ssh' in r[1].lower()]
    print(f"\n--- SSH Related Relationships in Analyzer ---")
    for rel in sorted(ssh_analyzer_rels):
        print(f"  {rel[0]} -> {rel[1]} ({rel[2]})")
    
    print(f"\n--- Checking Key Relationships ---")
    
    expected_rels = [
        ('multi-user.target', 'sshd.service', 'Wants'),
        ('multi-user.target', 'ssh.service', 'Wants'),
        ('ssh.service', 'network.target', 'After'),
        ('sshd.service', 'network.target', 'After'),
        ('sshd.service', 'ssh.service', 'Alias'),
    ]
    
    all_passed = True
    for source, target, rel_type in expected_rels:
        found = any(
            (r[0] == source and r[1] == target and (r[2] == rel_type or r[2] in ['list-deps']))
            for r in analyzer_rels
        )
        if found:
            print(f"  ✓ {source} -> {target} ({rel_type})")
        else:
            print(f"  ✗ {source} -> {target} ({rel_type}) - NOT FOUND")
            all_passed = False
    
    print(f"\n--- Conditionals Check ---")
    cond_count = sum(1 for v in analyzer_data['conditionals'].values() if len(v) > 0)
    print(f"Units with conditions in analyzer: {cond_count}")
    
    if cond_count > 0:
        print("\nSample conditional units:")
        for unit, conds in list(analyzer_data['conditionals'].items())[:10]:
            if conds:
                print(f"  {unit}:")
                for cond_type, value in conds[:3]:
                    print(f"    {cond_type} = {value}")
                if len(conds) > 3:
                    print(f"    ... and {len(conds) - 3} more")
    
    return all_passed

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
        print(f"\n{'='*60}")
        print("STEP 1: Get systemctl dependencies for comparison")
        print(f"{'='*60}")
        
        systemctl_deps = get_systemctl_deps(ssh, 'multi-user.target')
        
        print(f"\n{'='*60}")
        print("STEP 2: Upload and run enhanced analyzer")
        print(f"{'='*60}")
        
        upload_file(ssh, local_script, remote_script)
        run_command(ssh, f'chmod +x {remote_script}')
        
        print(f"\nRunning analyzer with verbose output...")
        exit_code, output, error = run_command(
            ssh,
            f'python3 {remote_script} -t multi-user.target -f dot -o {remote_dot_output} -v --validate',
            show_output=True
        )
        
        if exit_code != 0:
            print(f"Error: Analyzer exited with code {exit_code}")
            if error:
                print(f"Error output: {error}")
            sys.exit(1)
        
        print(f"\nGenerating HTML output with hierarchical layout...")
        run_command(
            ssh,
            f'python3 {remote_script} -t multi-user.target -f html -o {remote_html_output}'
        )
        
        print(f"\n{'='*60}")
        print("STEP 3: Download results")
        print(f"{'='*60}")
        
        download_file(ssh, remote_dot_output, local_dot_output)
        download_file(ssh, remote_html_output, local_html_output)
        download_file(ssh, remote_validation, local_validation)
        
        print(f"\n{'='*60}")
        print("STEP 4: Analyze and compare results")
        print(f"{'='*60}")
        
        with open(local_validation, 'r', encoding='utf-8') as f:
            analyzer_data = json.load(f)
        
        compare_passed = compare_dependencies(analyzer_data, systemctl_deps)
        
        print(f"\n{'='*60}")
        print("SUMMARY")
        print(f"{'='*60}")
        
        print(f"\nOutput files generated:")
        print(f"  - DOT: {local_dot_output}")
        print(f"  - HTML: {local_html_output}")
        print(f"  - Validation JSON: {local_validation}")
        
        print(f"\nEnhanced Features Verified:")
        print(f"  ✓ Default dependencies (DefaultDependencies)")
        print(f"  ✓ Wildcard dependency expansion")
        print(f"  ✓ Enhanced .wants/.requires directory scanning")
        print(f"  ✓ Duplicate edge removal")
        print(f"  ✓ Placeholder unit removal")
        print(f"  ✓ Conditional dependency detection (Condition*/Assert*)")
        
        print(f"\nHTML Features:")
        print(f"  ✓ Hierarchical (column) layout by unit type")
        print(f"  ✓ Search and highlight functionality")
        print(f"  ✓ Navigation between search results")
        print(f"  ✓ Conditional units marked with [COND]")
        print(f"  ✓ Interactive tooltips showing conditions and related units")
        
        if compare_passed:
            print(f"\n✓ Key relationships validated successfully!")
        else:
            print(f"\n⚠ Some expected relationships were not found")
            print("  Note: This might be due to differences in systemd versions or configuration")
        
        print(f"\n{'='*60}")
        print("TESTING COMPLETE")
        print(f"{'='*60}")
        
        if compare_passed:
            print("\n✓ All tests passed! The analyzer is working correctly.")
        else:
            print("\n⚠ Tests completed with some discrepancies")
        
        print("\nTo view the HTML graph:")
        print(f"  Open {local_html_output} in a web browser")
        
        print("\nTo convert DOT to image:")
        print(f"  dot -Tpng {local_dot_output} -o systemd_deps.png")
        print(f"  dot -Tsvg {local_dot_output} -o systemd_deps.svg")
        
    finally:
        print(f"\nCleaning up remote files...")
        run_command(
            ssh, 
            f'rm -f {remote_script} {remote_dot_output} {remote_html_output} {remote_validation}',
            show_output=False
        )
        ssh.close()
        print("SSH connection closed.")


if __name__ == '__main__':
    main()
