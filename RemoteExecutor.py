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
import socket
import select
import importlib.util
import re
import threading


from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler
from functools import partial


# Initialize colorama for colored logs
init()

class ColoredFormatter(logging.Formatter):
    """
    A custom logging formatter that adds color to log levels using colorama.
    """
    COLORS = {
        'DEBUG': Fore.GREEN,
        'INFO': Fore.BLUE,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA
    }
    RESET = Style.RESET_ALL

    def format(self, record):
        """
        Format the log record with color depending on the log level.
        """
        log_color = self.COLORS.get(record.levelname, self.RESET)
        levelname = f"{log_color}{record.levelname}{self.RESET}"
        record.levelname = levelname
        return super().format(record)


def configure_logger():
    """
    Configure the root logger to use the custom ColoredFormatter for colored logs.
    """
    handler = logging.StreamHandler()
    formatter = ColoredFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s')
    handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[handler])


# Call logger configuration
configure_logger()


def read_until_prompt(channel, prompt_re, timeout=30, print_live=False):
    """
    Read from the channel until the prompt_re pattern is detected or a timeout occurs.

    Args:
        channel (paramiko.Channel): The SSH channel to read from.
        prompt_re (Pattern): Compiled regex pattern for prompt detection.
        timeout (int): Timeout in seconds.
        print_live (bool): Whether to print output live.

    Returns:
        str: Accumulated output from the channel.

    Raises:
        TimeoutError: If prompt not detected within the timeout.
    """
    output = ""
    start_time = time.time()
    while True:
        if channel.recv_ready():
            data = channel.recv(4096).decode(errors="ignore")
            output += data
            if print_live:
                print(data, end="")
        if prompt_re.search(output):
            break
        if time.time() - start_time > timeout:
            raise TimeoutError(f"Prompt not detected within {timeout} seconds.")
        time.sleep(0.1)
    return output


def is_private_key(credential):
    """
    Check if the provided credential is a private key file.

    Args:
        credential (str): The path to the credential file.

    Returns:
        bool: True if the credential is a private key file, False otherwise.
    """
    return os.path.isfile(credential) and credential.endswith(".pem")


def validate_target_info(target):
    """
    Validate that the required fields (ip, username, credential, port) exist in the target.

    Args:
        target (dict): The target dictionary containing host information.

    Raises:
        ValueError: If any required fields are missing or invalid.
    """
    required_fields = ["ip", "username", "credential", "port"]
    for field in required_fields:
        if field not in target:
            raise ValueError(f"Missing required target field: {field}")
    if not isinstance(target["port"], int):
        raise ValueError("Target port must be an integer.")


class SSHOptions:
    """
    Defines default SSH connection options and provides a method to merge custom options.
    """
    DEFAULT_OPTIONS = {
        "timeout": 30,
        "allow_agent": False,
        "look_for_keys": False,
        "banner_timeout": 30,
        "auth_timeout": 30,
    }

    @staticmethod
    def get_ssh_options(custom_options=None):
        """
        Merge default SSH options with any custom options.

        Args:
            custom_options (dict): Custom SSH options to override the defaults.

        Returns:
            dict: A dictionary containing the merged SSH options.
        """
        options = SSHOptions.DEFAULT_OPTIONS.copy()
        if custom_options:
            options.update(custom_options)
        return options


class RemoteExecutor:
    """
    A class responsible for managing SSH connections, executing commands,
    handling remote tasks, port forwarding, and SOCKS5 proxies.
    """

    def __init__(self, hostname, username, credential=None, port=22,
                 jump_servers=None, ssh_options=None):
        """
        Initialize the RemoteExecutor instance.

        Args:
            hostname (str): The hostname or IP address of the target system.
            username (str): The username to authenticate with.
            credential (str): The password or path to a private key (.pem).
            port (int): The SSH port on the target system.
            jump_servers (list): List of jump server information dictionaries.
            ssh_options (dict): Additional SSH options to override defaults.
        """
        self.hostname = hostname
        self.username = username
        self.credential = credential
        self.port = port
        self.jump_servers = jump_servers or []
        self.ssh_options = SSHOptions.get_ssh_options(ssh_options)
        self.client = None
        self.jump_clients = []
        self.regular_channel = None
        self.elevated_channel = None

        # Keep track of any forwarding threads and servers to close them gracefully
        self.forwarding_threads = []
        self._stop_forwarding = threading.Event()
        self._port_forward_servers = []

    def _connect_to_jump_server(self, jump, sock, jump_elevate):
        """
        Connect to a single jump server and optionally elevate the shell.

        Args:
            jump (dict): Details of the jump server (IP, username, credential, port).
            sock (socket): The socket for the connection.
            jump_elevate (str): Command to elevate privileges on the jump server.

        Returns:
            tuple: A tuple containing the jump client and the channel (if elevated).
        """
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

            if jump_elevate:
                channel = jump_client.invoke_shell()
                channel.send(f"{jump_elevate}\n")
                time.sleep(1)
                if channel.recv_ready():
                    output = channel.recv(4096).decode(errors="ignore")
                    logging.info(f"Jump server elevation output: {output.strip()}")
                return jump_client, channel

            return jump_client, None

        except Exception as e:
            logging.error(f"Failed to connect to jump server {jump['ip']}: {e}")
            return None, None

    def _connect_jump_chain(self, jump_elevate):
        """
        Establish a chain of SSH connections through multiple jump servers.

        Args:
            jump_elevate (str): Command to elevate privileges on the final jump server.

        Returns:
            socket: The final socket connection for the target host, or None if failed.
        """
        sock = None
        for index, jump in enumerate(self.jump_servers):
            for field in ["ip", "username", "credential", "port"]:
                if field not in jump:
                    logging.error(f"Jump server missing required field: {field}. Aborting chain.")
                    return None

            jump_client, elevated_channel = self._connect_to_jump_server(jump, sock, jump_elevate)
            if not jump_client:
                logging.error(f"Failed to connect to jump server {jump.get('ip', 'Unknown')}. Aborting jump chain.")
                return None

            self.jump_clients.append(jump_client)

            if index == len(self.jump_servers) - 1:
                target = (self.hostname, self.port)
            else:
                target = (self.jump_servers[index + 1]["ip"], self.jump_servers[index + 1]["port"])

            try:
                sock = jump_client.get_transport().open_channel(
                    "direct-tcpip", target, ("127.0.0.1", 0)
                )
            except Exception as e:
                logging.error(f"Failed to open channel to {target[0]}:{target[1]} via jump server {jump['ip']}: {e}")
                return None

        return sock

    def connect(self, elevate_command="sudo su", jump_elevate=None, target_elevate=None):
        """
        Establish an SSH connection, optionally chaining through jump servers and elevating privileges.

        Args:
            elevate_command (str): Command to elevate privileges on the target system.
            jump_elevate (str): Command to elevate privileges on the jump server.
            target_elevate (str): Command to elevate privileges on the target system.

        Raises:
            paramiko.AuthenticationException: If authentication fails.
            Exception: For other connection issues.
        """
        try:
            sock = None
            if self.jump_servers:
                sock = self._connect_jump_chain(jump_elevate)
                if sock is None:
                    raise ConnectionError("Failed to establish complete jump server chain.")

            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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

            self._setup_channel()

            if target_elevate:
                self._elevate_channel(target_elevate)

        except paramiko.AuthenticationException as e:
            logging.error(f"Authentication failed for {self.hostname}: {e}")
            raise
        except Exception as e:
            logging.error(f"Connection failed for {self.hostname}: {e}")
            raise

    def _setup_channel(self):
        """
        Set up the regular (non-elevated) SSH channel and wait for it to be ready.
        """
        self.regular_channel = self.client.invoke_shell()
        self._wait_for_channel_ready(self.regular_channel)
        logging.info("Non-elevated channel ready.")

    def _elevate_channel(self, target_elevate):
        """
        Elevate the SSH channel and execute the elevation command.

        Args:
            target_elevate (str): Command to elevate privileges on the target system.
        """
        self.elevated_channel = self.client.invoke_shell()
        self._wait_for_channel_ready(self.elevated_channel)
        self.elevated_channel.send(f"{target_elevate}\n")
        time.sleep(1)
        if self.elevated_channel.recv_ready():
            output = self.elevated_channel.recv(4096).decode(errors="ignore")
            logging.info(f"Elevated channel ready with target elevation: {output.strip()}")

    def _wait_for_channel_ready(self, channel, timeout=10):
        """
        Wait for the SSH channel to become ready.

        Args:
            channel (paramiko.Channel): The SSH channel to check.
            timeout (int): Timeout in seconds to wait for the channel to become ready.

        Raises:
            TimeoutError: If the channel is not ready within the specified timeout.
        """
        start_time = time.time()
        while not channel.recv_ready():
            time.sleep(0.1)
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Channel did not become ready within {timeout} seconds.")

    def execute_command(self, command):
        """
        Execute a command on the target system using the appropriate channel.

        Args:
            command (str): The command to execute.

        Returns:
            str: The output of the executed command.

        Raises:
            Exception: If command execution fails.
        """
        try:
            channel = self.elevated_channel if self.elevated_channel else self.regular_channel
            channel.send(f"{command}\n")
            prompt_re = re.compile(r"([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+[:~\$\#\>\s]+)", re.MULTILINE)
            output = read_until_prompt(channel, prompt_re, timeout=30, print_live=True)
            logging.info(f"Command Output ({'Elevated' if self.elevated_channel else 'Regular'}):\n{output.strip()}")
            return output.strip()
        except Exception as e:
            logging.exception(f"Failed to execute command: {e}")
            raise

    def _capture_output(self, channel):
        """
        Capture the output from the given SSH channel.

        Args:
            channel (paramiko.Channel): The SSH channel from which to capture output.

        Returns:
            str: The captured output.
        """
        output = ""
        while channel.recv_ready():
            output += channel.recv(4096).decode(errors="ignore")
        return output

    def disconnect(self):
        """
        Disconnect SSH sessions, including any jump server sessions and
        close any forwarding threads and servers.
        """
        # Stop forwarding services gracefully
        self.stop_forwarding()

        if self.client:
            self.client.close()

        for jump_client in self.jump_clients:
            jump_client.close()

    def stop_forwarding(self):
        """
        Signal forwarding threads and servers to stop and close server sockets.
        """
        self._stop_forwarding.set()
        for server in self._port_forward_servers:
            try:
                server.close()
            except Exception as e:
                logging.error(f"Error closing port forward server: {e}")

    def execute_file_task(self, task):
        """
        Handle the execution of file-type tasks.

        Args:
            task (dict): A dictionary describing the file task, including:
                local_file (str): Path to the local file to be uploaded.
                remote_path (str): Where on the target the file will be placed.
                cleanup (bool): Whether to remove the remote file after execution.

        Returns:
            str: The combined output from the script execution and cleanup steps.

        Raises:
            Exception: If any part of the upload or execution fails.
        """
        local_file_path = task["local_file"]
        remote_file_path = task["remote_path"]
        cleanup = task.get("cleanup", True)

        try:
            script_name = os.path.basename(local_file_path)
            results_dir = "./results"
            os.makedirs(results_dir, exist_ok=True)
            hostname_safe = self.hostname.replace(":", "_").replace(".", "_")
            log_file_name = os.path.join(results_dir, f"{hostname_safe}_{script_name}_execution.log")

            with self.client.open_sftp() as sftp:
                sftp.put(local_file_path, remote_file_path)
            logging.info(f"Uploaded {local_file_path} to {remote_file_path}")

            execute_command = f"chmod +x {remote_file_path} && {remote_file_path}"
            logging.info(f"Executing command: {execute_command}")
            channel = self.elevated_channel if self.elevated_channel else self.regular_channel
            channel.send(f"{execute_command}\n")
            time.sleep(1)

            prompt_re = re.compile(r"([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+[:~\$\#\>\s]+)", re.MULTILINE)
            output = read_until_prompt(channel, prompt_re, timeout=60, print_live=True)

            with open(log_file_name, "a") as log_file:
                log_file.write(f"==== Command Execution on {self.hostname} ====\n")
                log_file.write(f"Command: {execute_command}\n")
                log_file.write(f"Output:\n{output}\n")
                log_file.write("=======================================\n")

            if cleanup:
                cleanup_command = f"rm -f {remote_file_path}"
                logging.info(f"Deleting remote file: {remote_file_path}")
                channel.send(f"{cleanup_command}\n")
                time.sleep(1)
                # Optionally, capture any final output post cleanup.
                while channel.recv_ready():
                    output += channel.recv(4096).decode(errors="ignore")

            logging.info(f"Execution Output for {script_name} on {self.hostname}")
            logging.info(f"Command Output:\n{output.strip()}")
            return output.strip()

        except Exception as e:
            logging.error(f"Failed to execute task on {self.hostname}: {e}")
            raise

    def encode_file_b64(self, input_path):
        """
        Read a file in binary mode and return its base64-encoded string.
        """
        with open(input_path, 'rb') as f:
            raw_data = f.read()
        return base64.b64encode(raw_data).decode("utf-8", errors="ignore")

    def decode_file_b64(self, b64_string, output_path):
        """
        Decode a base64 string back into its original bytes and write to output file.
        """
        decoded_data = base64.b64decode(b64_string.encode('ascii'))
        with open(output_path, 'wb') as f:
            f.write(decoded_data)

    def execute_fileless_task(self, task):
        """
        Execute a script filelessly on the remote system without writing to disk.

        Args:
            task (dict): Contains at least 'local_file' key.

        Returns:
            str: The output from the fileless script execution.

        Raises:
            Exception: If execution fails.
        """
        local_file_path = task["local_file"]

        try:
            encoded_script = self.encode_file_b64(local_file_path)
            chunk_size = 1000
            total_length = len(encoded_script)
            remote_command = "base64 -d | bash"
            logging.info(f"Initiating fileless execution on {self.hostname} without disk usage.")
            stdin, stdout, stderr = self.client.exec_command(remote_command)

            for i in range(0, total_length, chunk_size):
                chunk = encoded_script[i:i + chunk_size]
                stdin.write(chunk)
            stdin.channel.shutdown_write()

            output = stdout.read().decode(errors="ignore")
            error_output = stderr.read().decode(errors="ignore")

            if error_output:
                logging.error(f"Error during remote execution: {error_output}")

            logging.info(f"Script execution output:\n{output}")
            return output

        except Exception as e:
            logging.error(f"Failed to execute fileless task on {self.hostname}: {e}")
            raise

    def run_tasks(self, tasks):
        """
        Run a series of tasks on the remote system.

        Args:
            tasks (list): A list of task dictionaries to execute.
        """
        for task in tasks:
            try:
                self._run_task(task)
            except Exception as e:
                logging.error(f"Task failed on {self.hostname}: {e}")

    def _run_task(self, task):
        """
        Execute a single task based on its type (file, fileless, benchmark).

        Args:
            task (dict): The task dictionary to execute.
        """
        task_type = task.get("type", "file")
        if task_type == "file":
            self.execute_file_task(task)
        elif task_type == "fileless":
            self.execute_fileless_task(task)
        elif task_type == "benchmark":
            logging.info("Benchmark task is not yet implemented.")
        else:
            logging.warning(f"Unknown task type '{task_type}' for {self.hostname}. Skipping.")

    def start_port_forwarding(self, local_port, remote_host, remote_port):
        """
        Start a local port forwarding from localhost:local_port
        to remote_host:remote_port through this SSH connection.

        Args:
            local_port (int): The local port to listen on.
            remote_host (str): The remote host to forward traffic to.
            remote_port (int): The remote port to forward traffic to.
        """
        transport = self.client.get_transport()

        if not transport:
            logging.error("No active SSH transport found. Connect first.")
            return

        def forward_handler(client_socket):
            try:
                chan = transport.open_channel(
                    kind="direct-tcpip",
                    dest_addr=(remote_host, remote_port),
                    src_addr=client_socket.getsockname()
                )
            except Exception as e:
                logging.error(f"Failed to create channel for port forwarding: {e}")
                return

            if chan is None:
                logging.error("Could not open channel. Is the remote side open?")
                return

            while True:
                r, w, x = select.select([client_socket, chan], [], [])
                if client_socket in r:
                    data = client_socket.recv(1024)
                    if len(data) == 0:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(1024)
                    if len(data) == 0:
                        break
                    client_socket.send(data)
            chan.close()
            client_socket.close()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", local_port))
        server.listen(5)
        server.settimeout(1)  # To periodically check for stop signal
        self._port_forward_servers.append(server)
        logging.info(f"Forwarding local port {local_port} to {remote_host}:{remote_port}")

        def server_thread():
            while not self._stop_forwarding.is_set():
                try:
                    client_socket, addr = server.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=forward_handler, args=(client_socket,), daemon=True).start()

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()
        self.forwarding_threads.append(t)

    def start_socks5_proxy(self, local_port=1080):
        """
        Start a SOCKS5 proxy on the given local port that uses this SSH transport.

        Args:
            local_port (int): Local port on which to start the SOCKS5 proxy.
        """
        transport = self.client.get_transport()

        if not transport:
            logging.error("No active SSH transport found. Connect first.")
            return

        logging.info(f"Starting SOCKS5 proxy at 127.0.0.1:{local_port}. Use with caution in production!")

        from paramiko.forward import _create_forward_in_channel

        def socks_handler():
            try:
                paramiko.forward._start_socks_server(
                    transport=transport,
                    local_addr=("127.0.0.1", local_port),
                    handler=_create_forward_in_channel
                )
            except Exception as e:
                logging.error(f"Failed to start SOCKS5 proxy: {e}")

        t = threading.Thread(target=socks_handler, daemon=True)
        t.start()
        self.forwarding_threads.append(t)


def process_single_target(target, jump_servers, tasks):
    """
    Connect to a single target, run all tasks, and disconnect upon completion.

    Args:
        target (dict): Target information (ip, username, credential, port, etc.).
        jump_servers (list): List of jump server dictionaries, if any.
        tasks (list): List of tasks to run on this target.
    """
    try:
        validate_target_info(target)
    except ValueError as val_err:
        logging.error(f"Invalid target configuration: {val_err}")
        return

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

        if "port_forwarding" in target:
            pf_list = target["port_forwarding"]
            if isinstance(pf_list, list):
                for pf in pf_list:
                    local_port = pf.get("local_port")
                    remote_host = pf.get("remote_host")
                    remote_port = pf.get("remote_port")
                    if local_port and remote_host and remote_port:
                        checker.start_port_forwarding(local_port, remote_host, remote_port)
                    else:
                        logging.warning(f"Port forwarding config incomplete: {pf}")
            else:
                logging.warning(f"Port forwarding config must be a list: {pf_list}")

        if "socks5_proxy" in target:
            sp = target["socks5_proxy"]
            if isinstance(sp, dict):
                local_port = sp.get("local_port", 1080)
                checker.start_socks5_proxy(local_port)
            else:
                logging.warning(f"SOCKS5 proxy config must be a dict: {sp}")

        if tasks:
            checker.run_tasks(tasks)

    except Exception as e:
        logging.error(f"Error processing {target['ip']}: {e}")

    finally:
        checker.disconnect()


def main(config_file):
    """
    Main function to load the configuration file and run the tasks concurrently.

    Args:
        config_file (str): Path to the configuration file.
    """
    try:
        with open(config_file, "r") as f:
            config = json.load(f)

        jump_servers = config.get("jump_servers", [])
        tasks = config.get("tasks", [])

        for js in jump_servers:
            for field in ["ip", "username", "credential", "port"]:
                if field not in js:
                    logging.warning(f"Jump server config missing '{field}' field: {js}")

        targets = config.get("targets", [])
        if not targets:
            logging.warning("No targets found in the configuration.")
            return

        max_threads = 5
        futures = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for target in targets:
                futures.append(executor.submit(process_single_target, target, jump_servers, tasks))

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as ex:
                    logging.error(f"Unhandled exception in a thread: {ex}")

    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
    except json.JSONDecodeError as je:
        logging.error(f"JSON parsing error in configuration file: {je}")
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 refactored.py <config_file.json>")
        sys.exit(1)

    config_file = sys.argv[1]
    main(config_file)

