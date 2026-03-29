"""
Author: Mudit Markan
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and OS name
print("Python Version:", platform.python_version())
print("Operating System:", os.name)


# This dictionary maps common port numbers to their associated network service names

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?

    # Using @property and @target.setter allows controlled access to the private attribute
    # self.__target, enforcing validation logic whenever the value is read or changed.
    # Direct access to self.__target from outside the class is prevented, which follows
    #The principle of encapsulation and makes the code safer and easier to maintain.


    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?

# PortScanner inherits from NetworkTool, which means it automatically gains the target
# property, its getter/setter validation logic, and the destructor without rewriting them.
# For example, calling super().__init__(target) in PortScanner's constructor reuses
# NetworkTool's __init__ to store and validate the target IP address.



class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):


        # Q4: What would happen without try-except here?

        # Without try-except, any connection failure or timeout would raise an unhandled
        # exception and crash the entire program, especially when scanning unreachable ports.
        # On an unreachable machine, connect_ex would raise a socket.error or the timeout
        # would cause an exception that propagates up and terminates the thread unexpectedly.


        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            if sock:
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]



    # Q2: Why do we use threading instead of scanning one port at a time?

    # Threading allows multiple ports to be scanned concurrently, dramatically reducing
    # total scan time since each port scan waits up to 1 second for a timeout response.
    # Scanning 1024 ports sequentially without threads could take over 17 minutes in the
    # worst case, whereas threads let all scans run in parallel and finish in seconds.


    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, result[0], result[1], result[2], str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        for row in rows:
            # row: (id, target, port, status, service, scan_date)
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.OperationalError:
        print("No past scans found.")



# ============================================================
# MAIN PROGRAM
# ============================================================



if __name__ == "__main__":
    # Get target IP
    target_input = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    target = target_input if target_input else "127.0.0.1"

    # Get start port
    start_port = None
    while start_port is None:
        try:
            start_port = int(input("Enter start port (1-1024): "))
            if not (1 <= start_port <= 1024):
                print("Port must be between 1 and 1024.")
                start_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Get end port
    end_port = None
    while end_port is None:
        try:
            end_port = int(input("Enter end port (1-1024): "))
            if not (1 <= end_port <= 1024):
                print("Port must be between 1 and 1024.")
                end_port = None
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
                end_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("---")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if history == "yes":
        load_past_scans()


# Q5: New Feature Proposal

# A useful addition would be an export-to-CSV feature that saves all open port results
# to a .csv file for easy sharing and analysis. It would use a list comprehension to
# filter only open ports from scan_results, then write each row using Python's csv module
# with a nested if-statement to label high-risk ports (like 23 Telnet or 3389 RDP) as "Warning".
# Diagram: See diagram_101575511.png in the repository root


