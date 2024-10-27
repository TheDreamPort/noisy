#!/usr/bin/env python3
import paramiko
import paramiko.client
from requests import get
import requests
from urllib3.exceptions import LocationParseError
from sched2 import scheduler


def list_files(hostname, username, password, remote_path='/etc'):
    """List files in a remote directory using Paramiko."""

    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the server
        ssh.connect(hostname, username=username, password=password)

        # Open an SFTP session
        sftp = ssh.open_sftp()

        # List files in the remote directory
        files = sftp.listdir(remote_path)

        # Print the list of files
        for file in files:
            print(file)

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Close the SFTP and SSH connections
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

if __name__ == "__main__":
    print( "listing files in /etc/" )
    list_files('10.0.0.104', 'developer', '<PASSWORD>')
