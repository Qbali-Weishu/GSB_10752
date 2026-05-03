#!/usr/bin/env python3
"""
Test sudo access for ubuntu user.
"""

import paramiko
import os

def load_env_config():
    """Load host and password from .env file."""
    config = {}
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    
    return config

def run_with_sudo(ssh, command, password):
    """Run a command with sudo, providing password if needed."""
    sudo_command = f"sudo -S {command}"
    print(f"\n>>> Running with sudo: {command}")
    
    stdin, stdout, stderr = ssh.exec_command(sudo_command)
    stdin.write(password + '\n')
    stdin.flush()
    
    exit_code = stdout.channel.recv_exit_status()
    output = stdout.read().decode('utf-8', errors='ignore')
    error = stderr.read().decode('utf-8', errors='ignore')
    
    if output:
        print("Output:")
        print(output)
    if error:
        print("Error:")
        print(error)
    print(f"Exit code: {exit_code}")
    
    return exit_code, output, error

def main():
    config = load_env_config()
    host = config.get('host')
    password = config.get('password')
    
    print(f"Connecting to {host} as ubuntu...")
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=host,
        port=22,
        username='ubuntu',
        password=password,
        timeout=10,
        look_for_keys=False,
        allow_agent=False
    )
    
    print("Connected!")
    
    # Test if we can run systemctl without sudo
    print("\n" + "="*50)
    print("Testing systemctl without sudo:")
    print("="*50)
    stdin, stdout, stderr = ssh.exec_command('systemctl list-units --type=service --no-pager | head -10')
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    if output:
        print("Output:")
        print(output)
    if error:
        print("Error:")
        print(error)
    
    # Test if we can read systemd unit files
    print("\n" + "="*50)
    print("Testing reading systemd unit files:")
    print("="*50)
    stdin, stdout, stderr = ssh.exec_command('ls -la /etc/systemd/system/ 2>/dev/null | head -10')
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    if output:
        print("/etc/systemd/system/:")
        print(output)
    if error:
        print("Error:")
        print(error)
    
    stdin, stdout, stderr = ssh.exec_command('ls -la /usr/lib/systemd/system/ 2>/dev/null | head -10')
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    if output:
        print("/usr/lib/systemd/system/:")
        print(output)
    if error:
        print("Error:")
        print(error)
    
    # Test if sshd exists
    print("\n" + "="*50)
    print("Checking for sshd service:")
    print("="*50)
    stdin, stdout, stderr = ssh.exec_command('systemctl status sshd 2>/dev/null || systemctl status ssh 2>/dev/null')
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    if output:
        print("Output:")
        print(output[:500])
    if error:
        print("Error:")
        print(error)
    
    # Test if network.target exists and relationship to sshd
    print("\n" + "="*50)
    print("Checking sshd dependencies with systemctl:")
    print("="*50)
    stdin, stdout, stderr = ssh.exec_command('systemctl list-dependencies sshd 2>/dev/null || systemctl list-dependencies ssh 2>/dev/null')
    output = stdout.read().decode('utf-8')
    if output:
        print(output)
    
    # Check sshd service file
    print("\n" + "="*50)
    print("Checking sshd service file content:")
    print("="*50)
    stdin, stdout, stderr = ssh.exec_command('cat /lib/systemd/system/ssh.service 2>/dev/null || cat /usr/lib/systemd/system/sshd.service 2>/dev/null || cat /etc/systemd/system/sshd.service 2>/dev/null')
    output = stdout.read().decode('utf-8')
    if output:
        print(output)
    else:
        print("Could not find sshd service file in common locations")
        # Try to find it
        stdin, stdout, stderr = ssh.exec_command('systemctl show -p FragmentPath ssh.service 2>/dev/null || systemctl show -p FragmentPath sshd.service 2>/dev/null')
        output = stdout.read().decode('utf-8')
        if output:
            print(f"FragmentPath: {output.strip()}")
            # Read the actual file
            path = output.strip().split('=')[1] if '=' in output else output.strip()
            if path:
                stdin2, stdout2, stderr2 = ssh.exec_command(f'cat {path} 2>/dev/null')
                content = stdout2.read().decode('utf-8')
                if content:
                    print(f"\nContent of {path}:")
                    print(content)
    
    ssh.close()

if __name__ == '__main__':
    main()
