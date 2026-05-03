#!/usr/bin/env python3
"""
Remote testing script for systemd dependency analyzer.
Connects to remote server via SSH, runs the analyzer, and verifies results.
"""

import os
import sys
import paramiko
from scp import SCPClient
from io import StringIO

def load_env_config():
    """Load host and password from .env file."""
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
    
    if 'host' not in config:
        print("Error: 'host' parameter not found in .env file")
        sys.exit(1)
    if 'password' not in config:
        print("Error: 'password' parameter not found in .env file")
        sys.exit(1)
    
    return config

def create_ssh_client(host, password, username='ubuntu', port=22):
    """Create SSH client connection."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    print(f"Connecting to {host} as {username}...")
    print(f"Password length: {len(password)} characters")
    try:
        ssh.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False
        )
        print(f"Successfully connected to {host}")
        return ssh
    except paramiko.AuthenticationException as e:
        print(f"Error: Authentication failed for {host} - {e}")
        print(f"Please check username and password")
        sys.exit(1)
    except paramiko.SSHException as e:
        print(f"Error: SSH connection failed - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Connection failed - {e}")
        sys.exit(1)

def run_command(ssh, command, show_output=True):
    """Run a command on remote server."""
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
    """Upload a file to remote server using SCP."""
    print(f"\n>>> Uploading {local_path} to {remote_path}")
    
    with SCPClient(ssh.get_transport()) as scp:
        scp.put(local_path, remote_path)
    
    print(f"Successfully uploaded {local_path}")

def download_file(ssh, remote_path, local_path):
    """Download a file from remote server using SCP."""
    print(f"\n>>> Downloading {remote_path} to {local_path}")
    
    with SCPClient(ssh.get_transport()) as scp:
        scp.get(remote_path, local_path)
    
    print(f"Successfully downloaded {remote_path}")

def main():
    # Load configuration
    config = load_env_config()
    host = config['host']
    password = config['password']
    
    # Local files
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_script = os.path.join(script_dir, 'systemd_dep_analyzer.py')
    
    # Remote paths
    remote_script = '/tmp/systemd_dep_analyzer.py'
    remote_dot_output = '/tmp/systemd_deps.dot'
    remote_html_output = '/tmp/systemd_deps.html'
    
    # Local output paths
    local_dot_output = os.path.join(script_dir, 'systemd_deps.dot')
    local_html_output = os.path.join(script_dir, 'systemd_deps.html')
    
    # Create SSH connection
    ssh = create_ssh_client(host, password)
    
    try:
        # Check Python version on remote
        print("\n" + "="*60)
        print("Checking remote environment...")
        print("="*60)
        
        run_command(ssh, 'python3 --version')
        run_command(ssh, 'systemctl --version')
        
        # Upload the analyzer script
        print("\n" + "="*60)
        print("Uploading analyzer script to remote server...")
        print("="*60)
        
        upload_file(ssh, local_script, remote_script)
        
        # Make it executable
        run_command(ssh, f'chmod +x {remote_script}')
        
        # Run the analyzer with verbose output
        print("\n" + "="*60)
        print("Running systemd dependency analyzer on remote server...")
        print("="*60)
        
        # First run with verbose to check sshd and network.target
        print("\n--- Running verbose analysis for verification ---")
        exit_code, output, error = run_command(
            ssh, 
            f'python3 {remote_script} -t multi-user.target -f dot -o {remote_dot_output} -v'
        )
        
        # Check if sshd/ssh was found and its relationship to network.target
        print("\n" + "="*60)
        print("Verifying sshd/ssh and network.target relationship...")
        print("="*60)
        
        # Check for both ssh.service and sshd.service (they might be aliases)
        ssh_found = False
        if 'sshd.service found!' in output:
            print("✓ sshd.service was found in the analysis")
            ssh_found = True
        if 'ssh.service' in output:
            print("✓ ssh.service was found in the analysis")
            ssh_found = True
        
        if not ssh_found:
            print("⚠ Neither ssh.service nor sshd.service was explicitly mentioned in verbose output")
        
        # Also check using systemctl list-dependencies for comparison
        print("\n--- Checking with systemctl list-dependencies for comparison ---")
        # Try both ssh and sshd
        run_command(ssh, 'systemctl list-dependencies ssh.service 2>/dev/null || systemctl list-dependencies sshd.service 2>/dev/null')
        run_command(ssh, 'systemctl list-dependencies --after ssh.service 2>/dev/null || systemctl list-dependencies --after sshd.service 2>/dev/null')
        
        # Generate HTML output as well
        print("\n" + "="*60)
        print("Generating HTML output...")
        print("="*60)
        
        exit_code, output, error = run_command(
            ssh, 
            f'python3 {remote_script} -t multi-user.target -f html -o {remote_html_output}'
        )
        
        # Download the output files
        print("\n" + "="*60)
        print("Downloading output files from remote server...")
        print("="*60)
        
        download_file(ssh, remote_dot_output, local_dot_output)
        download_file(ssh, remote_html_output, local_html_output)
        
        # Analyze the DOT file locally for verification
        print("\n" + "="*60)
        print("Analyzing generated DOT file...")
        print("="*60)
        
        import re
        with open(local_dot_output, 'r', encoding='utf-8') as f:
            dot_content = f.read()
        
        # Function to check a service and its relationships
        def check_service(service_name):
            if service_name not in dot_content:
                return False, None, None
            
            print(f"✓ {service_name} found in DOT file")
            
            # Find all edges involving this service
            service_edges = re.findall(r'"' + re.escape(service_name) + r'"\s*->\s*"([^"]+)"\s*\[label="([^"]+)"', dot_content)
            service_targets = re.findall(r'"([^"]+)"\s*->\s*"' + re.escape(service_name) + r'"\s*\[label="([^"]+)"', dot_content)
            
            if service_edges:
                print(f"\n{service_name} depends on:")
                for target, rel_type in service_edges:
                    print(f"  - {target} ({rel_type})")
            
            if service_targets:
                print(f"\nUnits that depend on {service_name}:")
                for source, rel_type in service_targets:
                    print(f"  - {source} ({rel_type})")
            
            # Specifically check network.target relationship
            found_network_rel = False
            for target, rel_type in service_edges:
                if target == 'network.target':
                    print(f"\n✓ Found: {service_name} -> network.target ({rel_type})")
                    found_network_rel = True
            
            for source, rel_type in service_targets:
                if source == 'network.target':
                    print(f"\n✓ Found: network.target -> {service_name} ({rel_type})")
                    found_network_rel = True
            
            # Also check multi-user.target relationship
            for source, rel_type in service_targets:
                if source == 'multi-user.target':
                    print(f"\n✓ Found: multi-user.target -> {service_name} ({rel_type})")
            
            if not found_network_rel:
                print(f"\n⚠ No direct relationship found between {service_name} and network.target")
                print("  This is normal - sshd usually has After=network.target but not Requires/Wants")
            
            return True, service_edges, service_targets
        
        # Check both ssh.service and sshd.service (they might be aliases)
        ssh_found = False
        
        print("\n--- Checking ssh.service ---")
        found, edges, targets = check_service('ssh.service')
        if found:
            ssh_found = True
        
        print("\n--- Checking sshd.service ---")
        found, edges, targets = check_service('sshd.service')
        if found:
            ssh_found = True
        
        if not ssh_found:
            print("⚠ Neither ssh.service nor sshd.service found in DOT file")
        
        # Show summary of units found
        import re
        unit_matches = re.findall(r'"([^"]+)"\s*\[label="[^"]*", fillcolor="[^"]*"', dot_content)
        print(f"\nTotal units in graph: {len(unit_matches)}")
        
        # Count by type
        type_counts = {}
        for unit in unit_matches:
            if '.' in unit:
                unit_type = unit.split('.')[-1]
                type_counts[unit_type] = type_counts.get(unit_type, 0) + 1
        
        print("Units by type:")
        for unit_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"  - {unit_type}: {count}")
        
        print("\n" + "="*60)
        print("Testing complete!")
        print("="*60)
        print(f"\nOutput files generated:")
        print(f"  - DOT: {local_dot_output}")
        print(f"  - HTML: {local_html_output}")
        print("\nTo view the DOT file as an image:")
        print(f"  dot -Tpng {local_dot_output} -o systemd_deps.png")
        print("\nTo view the HTML file:")
        print(f"  Open {local_html_output} in a web browser")
        
    finally:
        # Clean up remote files
        print("\n" + "="*60)
        print("Cleaning up remote files...")
        print("="*60)
        
        run_command(ssh, f'rm -f {remote_script} {remote_dot_output} {remote_html_output}', show_output=False)
        
        # Close SSH connection
        ssh.close()
        print("\nSSH connection closed.")


if __name__ == '__main__':
    main()
