'''
Write a Python script that monitors a log file and alerts on failed SSH attempts or suspicious IPs.
'''

import re
import time
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"

FAILED_SSH_REGEX = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+) port")

FAILED_ATTEMPT_THRESHOLD = 5
ALERT_INTERVAL = 10  # seconds

failed_attempts = defaultdict(int)

def alert(ip, count):
    print(f"[ALERT] {count} failed SSH attempts from {ip}")

def monitor_log():
    print(f"Monitoring {LOG_FILE} for failed SSH logins: ")
    with open(LOG_FILE, "r") as f:
        # end of file
        # first param: positions of the read/write pointer to move within the file.
        # second param: default is 0, can be 1 which means seek relative to the current position and 2 means seek relative to the file's end.
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            match = FAILED_SSH_REGEX.search(line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
                if failed_attempts[ip] == FAILED_ATTEMPT_THRESHOLD:
                    alert(ip, failed_attempts[ip])


if __name__ == "__main__":
    try:
        monitor_log()
    except KeyboardInterrupt:
        print("\n Monitoring stopped.")
