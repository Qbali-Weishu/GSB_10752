#!/usr/bin/env python3
"""
Simple SSH connection test script.
"""

import paramiko
import os

def load_env_config():
    """Load host and password from .env file."""
    config = {}
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    
    if not os.path.exists(env_path):
        print(f"Error: .env file not found at {env_path}")
        return None
    
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    
    return config

def test_ssh():
    config = load_env_config()
    if not config:
        return
    
    host = config.get('host')
    password = config.get('password')
    
    print(f"Host: {host}")
    print(f"Password length: {len(password)}")
    print(f"Password starts with: {password[:3]}...")
    print(f"Password ends with: ...{password[-3:]}")
    
    # Try different usernames
    usernames_to_try = ['ubuntu', 'root', 'admin', 'centos', 'debian']
    
    for username in usernames_to_try:
        print(f"\n{'='*50}")
        print(f"Trying username: {username}")
        print(f"{'='*50}")
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
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
            print(f"✓ SUCCESS! Connected as {username}")
            
            # Test running a command
            stdin, stdout, stderr = ssh.exec_command('whoami && python3 --version')
            print(f"\nCommand output:")
            print(stdout.read().decode('utf-8'))
            
            ssh.close()
            return username
            
        except paramiko.AuthenticationException as e:
            print(f"✗ Authentication failed: {e}")
        except paramiko.SSHException as e:
            print(f"✗ SSH error: {e}")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    print("\nAll username attempts failed.")
    return None

if __name__ == '__main__':
    result = test_ssh()
    if result:
        print(f"\n*** Working username: {result} ***")
