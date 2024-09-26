import paramiko
import xml.etree.ElementTree as ET
import logging
import sys
import time
import re

# Setup logging
logging.basicConfig(filename='ise-log.txt', level=logging.DEBUG, format='%(asctime)s - %(message)s')

def read_config():
    # Parse the XML file
    tree = ET.parse('config.xml')
    root = tree.getroot()

    # Extract ISE, FTP, and backup details
    ise = root.find('ise')
    ftp = root.find('ftp')
    backup = root.find('backup')

    ise_config = {
        'hostname': ise.find('hostname').text,
        'username': ise.find('username').text,
        'password': ise.find('password').text
    }

    ftp_config = {
        'hostname': ftp.find('hostname').text,
        'username': ftp.find('username').text,
        'password': ftp.find('password').text,
        'backup_dir': ftp.find('backup_dir').text
    }

    encryption_key = backup.find('encryption_key')
    if encryption_key is None or len(encryption_key.text) < 8 or not any(char.isdigit() for char in encryption_key.text):
        logging.error("Error: Encryption key must be at least 8 characters long and contain at least one digit.")
        print("Error: Encryption key must be at least 8 characters long and contain at least one digit.")
        sys.exit(1)

    backup_config = {
        'name': backup.find('name').text,
        'encryption_key': encryption_key.text
    }

    return ise_config, ftp_config, backup_config

def ssh_connect(ise_config):
    logging.info(f"Connecting to ISE at {ise_config['hostname']} via SSH")
    
    try:
        # Initialize SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Establish connection
        ssh.connect(ise_config['hostname'], username=ise_config['username'], password=ise_config['password'])
        logging.info(f"Connected to ISE {ise_config['hostname']} successfully.")
        print(f"Connected to ISE {ise_config['hostname']} successfully.")
        
        return ssh
    except Exception as e:
        logging.error(f"SSH connection failed: {str(e)}")
        print(f"SSH connection failed: {str(e)}")
        return None

def execute_interactive_commands(ssh, commands):
    logging.info(f"Executing interactive commands")
    try:
        # Open an interactive shell session
        shell = ssh.invoke_shell()
        time.sleep(1)  # Wait for the shell to initialize

        shell.recv(1000)  # Clear any initial output

        for command in commands:
            logging.info(f"Sending command: {command}")
            shell.send(command + "\n")
            time.sleep(2)  # Give time for the command to execute

            # Read the output from the shell
            output = shell.recv(5000).decode("utf-8")
            logging.info(f"Command output: {output}")
            print(f"Command output: {output}")
            if "% Invalid" in output or "syntax error" in output or "% Repository not found" in output:
                logging.error(f"Error executing command: {command}")
                print(f"Error executing command: {command}")
                return False, output

        return True, output

    except Exception as e:
        logging.error(f"Interactive command execution failed: {str(e)}")
        print(f"Interactive command execution failed: {str(e)}")
        return False, str(e)

def check_repository_exists(ssh):
    logging.info("Checking if the repository exists")

    # Check if the repository exists using the interactive shell
    commands = ["show repository FTP-Repo"]
    success, output = execute_interactive_commands(ssh, commands)
    return success and "% Repository not found" not in output

def create_repository(ssh, ftp_config):
    logging.info("Creating repository FTP-Repo.")
    print("Creating repository FTP-Repo.")

    # Open an interactive shell session
    shell = ssh.invoke_shell()
    time.sleep(1)
    shell.recv(1000)  # Clear any initial output

    # Ensure that we are at the correct prompt before proceeding
    def wait_for_prompt(expected_prompt):
        while True:
            output = shell.recv(5000).decode("utf-8")
            if expected_prompt in output:
                break
            time.sleep(1)

    # Enter configuration mode
    shell.send("configure terminal\n")
    time.sleep(2)
    wait_for_prompt("ise60/admin(config)#")

    # Commands to create the FTP repository
    commands = [
        "repository FTP-Repo",
        f"url ftp://{ftp_config['hostname']}/",
        f"user {ftp_config['username']} password plain {ftp_config['password']}",
        "end"
    ]

    for command in commands:
        shell.send(command + "\n")
        time.sleep(2)

        # Read the output and confirm we're at the expected prompt
        output = shell.recv(5000).decode("utf-8")
        logging.info(f"Command output: {output}")
        print(f"Command output: {output}")

        # If any command produces an error, handle it
        if "syntax error" in output or "% Repository not found" in output:
            logging.error(f"Error executing command: {command}")
            print(f"Error executing command: {command}")
            break

    logging.info("FTP-Repo repository created successfully.")
    print("FTP-Repo repository created successfully.")


def retry_repository_check(ssh, max_retries=3):
    retries = 0
    while retries < max_retries:
        if check_repository_exists(ssh):
            return True
        retries += 1
        logging.info(f"Retrying repository check, attempt {retries}")
        time.sleep(5)  # Delay between retries

    return False

def monitor_backup(shell):
    logging.info("Monitoring backup progress...")
    print("Monitoring backup progress...")
    
    while True:
        output = shell.recv(5000).decode("utf-8")
        if output:
            print(output)
            logging.info(output)
            if "100% completed" in output:
                print("Backup completed successfully.")
                logging.info("Backup completed successfully.")
                break

def reset_application(ssh, admin_password):
    logging.info("Initiating reset using the 'application reset-config ise' command")
    print("Initiating reset using the 'application reset-config ise' command")

    shell = ssh.invoke_shell()
    time.sleep(1)
    shell.recv(1000)  # Clear any initial output

    # Send the reset command
    shell.send("application reset-config ise\n")
    time.sleep(2)

    # Monitor and handle prompts during reset
    while True:
        output = shell.recv(5000).decode("utf-8")
        if output:
            print(output)
            logging.info(output)

            # Respond to prompts as they appear
            if "Initialize your Application configuration to factory defaults? (y/n):" in output:
                logging.info("Responding 'y' to initialization confirmation prompt")
                shell.send("y\n")
                time.sleep(2)

            elif "Retain existing Application server certificates? (y/n):" in output:
                logging.info("Responding 'y' to retain certificates prompt")
                shell.send("y\n")
                time.sleep(2)

            elif "Enter the administrator username to create[admin]:" in output:
                logging.info("Responding 'admin' to username prompt")
                shell.send("admin\n")
                time.sleep(2)

            elif "Do you want to continue? (y/n):" in output:
                logging.info("Responding 'y' to continue prompt")
                shell.send("y\n")
                time.sleep(2)

            elif "Enter the password for 'admin':" in output:
                logging.info("Entering password for 'admin'")
                shell.send(f"{admin_password}\n")
                time.sleep(2)

            elif "Re-enter the password for 'admin':" in output:
                logging.info("Re-entering password for 'admin'")
                shell.send(f"{admin_password}\n")
                time.sleep(2)

            if "application reset-config is success" in output:
                logging.info("Reset completed successfully.")
                print("Reset completed successfully.")
                break
        else:
            time.sleep(1)

def initiate_backup(ssh, backup_config):
    logging.info(f"Initiating on-demand backup with name {backup_config['name']} on ISE")
    print(f"Initiating on-demand backup with name {backup_config['name']} on ISE")

    # Open an interactive shell session for the backup
    shell = ssh.invoke_shell()
    time.sleep(1)
    shell.recv(1000)  # Clear any initial output

    # Send the backup command
    command = f"backup {backup_config['name']} repository FTP-Repo ise-config encryption-key plain {backup_config['encryption_key']}"
    shell.send(command + "\n")
    time.sleep(2)

    backup_filename = None

    # Monitor the output for progress and the backup filename
    while True:
        output = shell.recv(5000).decode("utf-8")
        if output:
            print(output)
            logging.info(output)

            # Capture the backup filename
            match = re.search(r'% Creating backup with timestamped filename: (\S+)', output)
            if match:
                backup_filename = match.group(1)
                logging.info(f"Backup filename: {backup_filename}")
                # Write backup filename to a text file
                with open("backup_filename.txt", "w") as f:
                    f.write(backup_filename)
                print(f"Backup filename saved to backup_filename.txt")

            if "100% completed" in output:
                print("Backup completed successfully.")
                logging.info("Backup completed successfully.")
                break

    return backup_filename

def create_repository(ssh, ftp_config):
    logging.info("Creating repository FTP-Repo.")
    print("Creating repository FTP-Repo.")

    # Commands to create the FTP repository interactively
    commands = [
        "configure terminal",
        "repository FTP-Repo",
        f"url ftp://{ftp_config['hostname']}/",
        f"user {ftp_config['username']} password plain {ftp_config['password']}",
        "end"
    ]

    # Open an interactive shell session
    shell = ssh.invoke_shell()
    time.sleep(1)
    shell.recv(1000)  # Clear any initial output

    for command in commands:
        shell.send(command + "\n")
        time.sleep(2)

        output = shell.recv(5000).decode("utf-8")
        logging.info(f"Command output: {output}")
        print(f"Command output: {output}")

    logging.info("FTP-Repo repository created successfully.")
    print("FTP-Repo repository created successfully.")

def restore_backup(ssh, backup_filename, backup_config):
    logging.info(f"Restoring backup from file {backup_filename}")
    print(f"Restoring backup from file {backup_filename}")

    # Restore command
    command = f"restore {backup_filename} repository FTP-Repo encryption-key plain {backup_config['encryption_key']}"

    # Open an interactive shell session for the restore
    shell = ssh.invoke_shell()
    time.sleep(1)
    shell.recv(1000)  # Clear any initial output

    shell.send(command + "\n")
    time.sleep(2)

    # Monitor the restore process
    while True:
        output = shell.recv(5000).decode("utf-8")
        if output:
            print(output)
            logging.info(output)

            # Respond to any confirmation prompt to proceed with the restore
            if "Do you want to continue with restore?" in output:
                logging.info("Responding 'y' to restore confirmation")
                shell.send("y\n")
                time.sleep(2)

            # Check for completion message
            if "100% completed" in output:
                logging.info("Restore completed successfully.")
                print("Restore completed successfully.")
                break  # Break out of the loop once restore is confirmed as completed

def main():
    # Read the config from XML
    ise_config, ftp_config, backup_config = read_config()

    # Connect to ISE using SSH
    ssh = ssh_connect(ise_config)
    if ssh:
        try:
            # **Check if the repository already exists before creating it**
            if not check_repository_exists(ssh):
                logging.info("Repository not found, creating it.")
                create_repository(ssh, ftp_config)
            else:
                logging.info("Repository already exists, skipping creation.")

            # Initiate Backup
            backup_filename = initiate_backup(ssh, backup_config)

            # Once backup is completed, initiate the reset
            reset_application(ssh, ise_config['password'])

            # Wait 60 seconds for system stabilization after reset
            logging.info("Waiting 60 seconds for system to stabilize after reset.")
            print("Waiting 60 seconds for system to stabilize after reset.")
            time.sleep(60)

            # After reset, reconfigure the repository
            if not check_repository_exists(ssh):
                logging.info("Repository not found after reset, creating it.")
                create_repository(ssh, ftp_config)

            # Restore the backup from the file
            restore_backup(ssh, backup_filename, backup_config)

        finally:
            # Properly close the SSH session to prevent any idle timeout
            logging.info("Closing SSH session after all tasks are completed.")
            print("Closing SSH session after all tasks are completed.")
            ssh.close()
            logging.info("SSH session closed.")
            print("SSH session closed.")


if __name__ == '__main__':
    main()
