# William Coppola (SubINaclS) 2025
# Developed for use
# All rights reserved

import paramiko
import logging
import sys
import os
import json
import time
import base64
from colorama import Fore, Style, init
import socket
import select

# Initialize colorama for colored logs
init()

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.GREEN,
        'INFO': Fore.BLUE,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA
    }
    RESET = Style.RESET_ALL

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.RESET)
        levelname = f"{log_color}{record.levelname}{self.RESET}"  # Apply color only to the log level
        record.levelname = levelname
        return super().format(record)

def configure_logger():
    """Configure the root logger with a colorized formatter."""
    handler = logging.StreamHandler()
    formatter = ColoredFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s')
    handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[handler])

# Call logger configuration
configure_logger()

def is_private_key(credential):
    """Check if the credential is a private key file."""
    return os.path.isfile(credential) and credential.endswith(".pem")

class SSHOptions:
    """SSH Connection options."""
    DEFAULT_OPTIONS = {
        "timeout": 30,
        "allow_agent": False,
        "look_for_keys": False,
        "banner_timeout": 30,
        "auth_timeout": 30,
    }

    @staticmethod
    def get_ssh_options(custom_options=None):
        """Merge default options with any custom options."""
        options = SSHOptions.DEFAULT_OPTIONS.copy()
        if custom_options:
            options.update(custom_options)
        return options

class RemoteExecutor:
    def __init__(self, hostname, username, credential=None, port=22, jump_servers=None, ssh_options=None):
        self.hostname = hostname
        self.username = username
        self.credential = credential
        self.port = port
        self.jump_servers = jump_servers or []
        self.ssh_options = ssh_options or {}
        self.client = None
        self.jump_clients = []
        self.regular_channel = None
        self.elevated_channel = None

    def _connect_to_jump_server(self, jump, sock, jump_elevate):
        """Connect to a single jump server and optionally elevate the shell."""
        jump_client = paramiko.SSHClient()
        jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if is_private_key(jump["credential"]):
                pkey = paramiko.RSAKey.from_private_key_file(jump["credential"])
                jump_client.connect(
                    hostname=jump["ip"],
                    port=jump["port"],
                    username=jump["username"],
                    pkey=pkey,
                    sock=sock,
                    **self.ssh_options
                )
            else:
                jump_client.connect(
                    hostname=jump["ip"],
                    port=jump["port"],
                    username=jump["username"],
                    password=jump["credential"],
                    sock=sock,
                    **self.ssh_options
                )
            logging.info(f"Connected to jump server {jump['ip']}")
            # Elevate shell if jump_elevate is provided
            if jump_elevate:
                channel = jump_client.invoke_shell()
                channel.send(f"{jump_elevate}\n")
                time.sleep(1)
                if channel.recv_ready():
                    output = channel.recv(1024).decode()
                    logging.info(f"Jump server elevation output: {output.strip()}")
                return jump_client, channel
            return jump_client, None
        except Exception as e:
            logging.error(f"Failed to connect to jump server {jump['ip']}: {e}")
            return None, None

    def _connect_jump_chain(self, jump_elevate):
        """Create a chain of SSH connections through jump servers."""
        sock = None
        for index, jump in enumerate(self.jump_servers):
            jump_client, elevated_channel = self._connect_to_jump_server(jump, sock, jump_elevate)
            if not jump_client:
                logging.error(f"Failed to connect to jump server {jump['ip']}. Aborting jump chain.")
                return None
            self.jump_clients.append(jump_client)
            target = (self.hostname, self.port) if index == len(self.jump_servers) - 1 else (
                self.jump_servers[index + 1]["ip"], self.jump_servers[index + 1]["port"])
            sock = jump_client.get_transport().open_channel("direct-tcpip", target, ("127.0.0.1", 0))
        return sock

    def connect(self, elevate_command="sudo su", jump_elevate=None, target_elevate=None):
        """Establish SSH connection and optionally elevate shell."""
        try:
            sock = self._connect_jump_chain(jump_elevate) if self.jump_servers else None
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Determine whether the credential is a private key or password
            if is_private_key(self.credential):
                pkey = paramiko.RSAKey.from_private_key_file(self.credential)
                logging.info(f"Using private key authentication for {self.hostname}")
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    pkey=pkey,
                    sock=sock,
                    **self.ssh_options
                )
            else:
                logging.info(f"Using password authentication for {self.hostname}")
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    password=self.credential,
                    sock=sock,
                    **self.ssh_options
                )
            logging.info(f"Connected successfully to {self.hostname}")
            # Set up non-elevated channel
            self.regular_channel = self.client.invoke_shell()
            start_time = time.time()
            while not self.regular_channel.recv_ready():
                time.sleep(0.1)
                if time.time() - start_time > 10:
                    raise TimeoutError("Non-elevated channel did not become ready within 10 seconds.")
            logging.info("Non-elevated channel ready.")
            # Set up elevated channel if target_elevate is provided
            if target_elevate:
                self.elevated_channel = self.client.invoke_shell()
                start_time = time.time()
                while not self.elevated_channel.recv_ready():
                    time.sleep(0.1)
                    if time.time() - start_time > 10:
                        raise TimeoutError("Elevated channel did not become ready within 10 seconds.")
                self.elevated_channel.send(f"{target_elevate}\n")
                time.sleep(1)
                if self.elevated_channel.recv_ready():
                    output = self.elevated_channel.recv(1024).decode()
                    logging.info(f"Elevated channel ready with target elevation: {output.strip()}")
            else:
                self.elevated_channel = None
                logging.info("No elevated channel required.")
        except paramiko.AuthenticationException as e:
            logging.error(f"Authentication failed for {self.hostname}: {e}")
            raise
        except Exception as e:
            logging.error(f"Connection failed for {self.hostname}: {e}")
            raise

    def execute_command(self, command):
        """Execute a command on the target system using the appropriate channel."""
        try:
            channel = self.elevated_channel if self.elevated_channel else self.regular_channel
            channel.send(f"{command}\n")
            time.sleep(1)  # Allow time for command execution
            output = ""
            while channel.recv_ready():
                output += channel.recv(1024).decode()
            logging.info(f"Command Output ({'Elevated' if use_elevated else 'Regular'}):\n{output.strip()}")
            return output.strip()
        except Exception as e:
            logging.error(f"Failed to execute command: {e}")
            raise

    def disconnect(self):
        """Disconnect SSH sessions."""
        if self.client:
            self.client.close()
        for jump_client in self.jump_clients:
            jump_client.close()

    def load_benchmarks(self, benchmark_file):
        try:
            spec = importlib.util.spec_from_file_location("benchmarks", benchmark_file)
            benchmarks = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(benchmarks)
            self.benchmarks = benchmarks.benchmarks
            logging.info("Benchmarks loaded successfully.")
        except Exception as e:
            logging.error(f"Failed to load benchmarks: {e}")
            self.benchmarks = {}


    def run_benchmarks(self, benchmark_file):
        """
        Run benchmarks based on a Python dictionary loaded from a benchmark file.
        """
        try:
            # Dynamically load the benchmark file as a Python dictionary
            with open(benchmark_file, "r") as f:
                benchmarks = eval(f.read())  # Use eval carefully; safer alternatives can be used
            if not benchmarks:
                logging.error("No benchmarks found in the benchmark file. Please check the file.")
                return
        except Exception as e:
            logging.error(f"Failed to load benchmarks from file {benchmark_file}: {e}")
            return
        logging.info("Running benchmarks...")
        failed_tests = []
        ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])|(?:\[\d{2}:\d{2}:\d{2}\])|(?:[^\s]*\\$)')
        for benchmark_id, benchmark in benchmarks.items():
            desc = benchmark["desc"]
            command = benchmark["command"]
            criteria = benchmark.get("criteria", "No criteria provided.")
            validation = benchmark["validation"]
            logging.info(f"Running benchmark {benchmark_id}: {desc}")
            logging.info(f"Criteria: {criteria}")
            try:
                # Select appropriate channel based on elevation requirements
                channel, use_elevated = (self.elevated_channel, True) if self.elevated_channel else (self.regular_channel, False)
                # Send command to the remote system
                channel.send(f"{command}\n")
                time.sleep(1)  # Allow time for command execution
                # Capture command output
                output = ""
                while channel.recv_ready():
                    output += channel.recv(1024).decode()
                # Clean up the output for readability
                cleaned_output = "\n".join(
                    line for line in output.splitlines() if not ansi_escape.search(line)
                ).strip()
                # Validate the benchmark result
                result = validation(cleaned_output)
                if result == "PASS":
                    logging.info(f"Benchmark {benchmark_id} PASSED: {desc}")
                else:
                    logging.error(f"Benchmark {benchmark_id} FAILED: {desc}\nCriteria: {criteria}\nOutput:\n{cleaned_output}")
                    failed_tests.append((benchmark_id, desc, criteria, command, cleaned_output))
            except Exception as e:
                logging.error(f"Error executing benchmark {benchmark_id}: {e}")
                failed_tests.append((benchmark_id, desc, criteria, command, str(e)))
        # Report failed tests
        if failed_tests:
            logging.error("Some benchmarks failed:")
            for benchmark_id, desc, criteria, command, output in failed_tests:
                logging.error(f"ID: {benchmark_id}, Desc: {desc}\nCriteria: {criteria}\nCommand: {command}\nOutput:\n{output}")
        else:
            logging.info("All benchmarks passed successfully.")


    def execute_file_task(self, task):
        """Handle the execution of file-type tasks."""
        local_file_path = task["local_file"]
        remote_file_path = task["remote_path"]
        cleanup = task.get("cleanup", True)
        try:
            # Derive script name from local file path
            script_name = os.path.basename(local_file_path)
            # Ensure results directory exists
            results_dir = "./results"
            os.makedirs(results_dir, exist_ok=True)
            hostname_safe = self.hostname.replace(":", "_").replace(".", "_")
            log_file_name = os.path.join(results_dir, f"{hostname_safe}_{script_name}_execution.log")
            # Upload the script to the remote system
            sftp = self.client.open_sftp()
            sftp.put(local_file_path, remote_file_path)
            sftp.close()
            logging.info(f"Uploaded {local_file_path} to {remote_file_path}")
            # Execute the script
            execute_command = f"chmod +x {remote_file_path} && {remote_file_path}"
            logging.info(f"Executing command: {execute_command}")
            channel, use_elevated = (self.elevated_channel, True) if self.elevated_channel else (self.regular_channel, False)
            channel.send(f"{execute_command}\n")
            time.sleep(1)  # Allow time for command execution
            # Capture outputs
            output = ""
            while channel.recv_ready():
                output += channel.recv(1024).decode()
            # Log command output
            if log_file_name:
                with open(log_file_name, "a") as log_file:
                    log_file.write(f"==== Command Execution on {self.hostname} ====")
                    log_file.write(f"Command: {execute_command}\n")
                    log_file.write(f"Output:\n{output}\n")
                    log_file.write("=======================================\n")
            # Cleanup the file if required
            if cleanup:
                cleanup_command = f"rm -f {remote_file_path}"
                logging.info(f"Deleting remote file: {remote_file_path}")
                channel.send(f"{cleanup_command}\n")
                time.sleep(1)  # Allow time for command execution
                # Capture cleanup outputs
                while channel.recv_ready():
                    output += channel.recv(1024).decode()
            # Log results to the screen
            logging.info(f"Execution Output for {script_name} on {self.hostname}")
            logging.info(f"Command Output ({'Elevated' if use_elevated else 'Regular'}):\n{output.strip()}")
            return output.strip()
        except Exception as e:
            logging.error(f"Failed to execute task on {self.hostname}: {e}")
            raise

    def execute_fileless_task(self, task):
        """Execute a script fileless on the remote system."""
        local_file_path = task["local_file"]
        try:
            # Read the script content and encode it in base64
            with open(local_file_path, "r") as file:
                script_content = file.read()
            encoded_script = base64.b64encode(script_content.encode()).decode()
            # Ensure results directory exists
            results_dir = "./results"
            os.makedirs(results_dir, exist_ok=True)
            script_name = os.path.basename(local_file_path)
            log_file_name = os.path.join(results_dir, f"{self.hostname.replace(':', '_')}_{script_name}_execution.log")
            # Execute the command
            execute_command = f"echo '{encoded_script}' | base64 -d | bash -s --"
            logging.info(f"Sending base64-encoded script for execution on {self.hostname}.")
            channel, use_elevated = (self.elevated_channel, True) if self.elevated_channel else (self.regular_channel, False)
            channel.send(f"{execute_command}\n")
            time.sleep(1)  # Allow time for command execution
            # Capture outputs
            output = ""
            while channel.recv_ready():
                output += channel.recv(1024).decode()
            # Log command output
            if log_file_name:
                with open(log_file_name, "a") as log_file:
                    log_file.write(f"==== Command Execution on {self.hostname} ====")
                    log_file.write(f"Command: {execute_command}\n")
                    log_file.write(f"Output:\n{output}\n")
                    log_file.write("=======================================\n")
            # Log results to the screen
            logging.info(f"Execution Output for {script_name} on {self.hostname}")
            logging.info(f"Command Output ({'Elevated' if use_elevated else 'Regular'}):\n{output.strip()}")
            return output.strip()

        except Exception as e:
            logging.error(f"Failed to execute fileless task on {self.hostname}: {e}")
            raise

    def run_tasks(self, tasks):
        """Run tasks for this host."""
        for task in tasks:
            task_type = task.get("type", "file")
            try:
                if task_type == "file":
                    self.execute_file_task(task)
                elif task_type == "fileless":
                    self.execute_fileless_task(task)
                elif task_type == "benchmark":
                    self.run_benchmarks()
                else:
                    logging.warning(f"Unknown task type '{task_type}' for {self.hostname}. Skipping.")
            except Exception as e:
                logging.error(f"Task failed on {self.hostname}: {e}")

    def start_port_forwarding(self, local_port, remote_host, remote_port):
        """Set up port forwarding from a local port to a remote port."""
        try:
            logging.info(f"Starting port forwarding: localhost:{local_port} -> {remote_host}:{remote_port}")
            transport = self.client.get_transport()
            transport.request_port_forward("", local_port, self._port_forward_handler(remote_host, remote_port))
            logging.info(f"Port forwarding established: localhost:{local_port} -> {remote_host}:{remote_port}")
        except Exception as e:
            logging.error(f"Failed to start port forwarding: {e}")
            raise

    def _port_forward_handler(self, remote_host, remote_port):
        """Create a named function for handling channel forwarding."""
        def handler(channel):
            self._forward_to_remote(channel, remote_host, remote_port)
        return handler

    def _forward_to_remote(self, channel, remote_host, remote_port):
        """Forward the local channel to the remote host and port."""
        sock = socket.socket()
        try:
            sock.connect((remote_host, remote_port))
            logging.info(f"Forwarding channel to {remote_host}:{remote_port}")
        except Exception as e:
            logging.error(f"Unable to connect to {remote_host}:{remote_port}: {e}")
            return
        start_time = time.time()
        timeout = 30  # Timeout after 30 seconds to prevent indefinite hanging
        while True:
            r, _, _ = select.select([channel, sock], [], [], 1.0)
            if not r:
                # Check for timeout condition
                if time.time() - start_time > timeout:
                    logging.error(f"Timeout occurred during forwarding to {remote_host}:{remote_port}")
                    break
                continue
            if channel in r:
                data = channel.recv(1024)
                if len(data) == 0:
                    break
                sock.send(data)
            if sock in r:
                data = sock.recv(1024)
                if len(data) == 0:
                    break
                channel.send(data)
        channel.close()
        sock.close()

    def start_socks5_proxy(self, local_port):
        """Set up a SOCKS5 proxy on the specified local port."""
        try:
            logging.info(f"Starting SOCKS5 proxy on localhost:{local_port}")
            transport = self.client.get_transport()
            if not self._is_port_available(local_port):
                raise Exception(f"Local port {local_port} is not available.")
            transport.set_tunnel(local_port)
            logging.info(f"SOCKS5 proxy established on localhost:{local_port}")
        except Exception as e:
            logging.error(f"Failed to start SOCKS5 proxy: {e}")
            raise

    def _is_port_available(self, port):
        """Check if the local port is available."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) != 0

def main(config_file):
    with open(config_file, "r") as f:
        config = json.load(f)
    jump_servers = config.get("jump_servers", [])
    tasks = config.get("tasks", [])
    for target in config.get("targets", []):
        checker = RemoteExecutor(
            hostname=target["ip"],
            username=target["username"],
            credential=target["credential"],
            port=target["port"],
            jump_servers=jump_servers,
            ssh_options=target.get("ssh_options")
        )
        try:
            checker.connect(target_elevate=target.get("target_elevate"))
            # Handle Port Forwarding
            if "port_forwarding" in target:
                pf = target["port_forwarding"]
                checker.start_port_forwarding(pf["local_port"], pf["remote_host"], pf["remote_port"])
            # Handle SOCKS5 Proxy
            if "socks5_proxy" in target:
                sp = target["socks5_proxy"]
                checker.start_socks5_proxy(sp["local_port"])
            # Run tasks if any
            if tasks:
                checker.run_tasks(tasks)
        except Exception as e:
            logging.error(f"Error processing {target['ip']}: {e}")
        finally:
            checker.disconnect()

if __name__ == "__main__":
    main(sys.argv[1])
