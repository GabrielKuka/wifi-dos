from asyncio.subprocess import DEVNULL
import subprocess, os, re 
from colorama import Fore, Style

ATTACK_ALL = 1
SELECT_VICTIM = 2

def cmd(cmd):
    return cmd.split(' ')

def error(msg):
    return f"{Fore.RED}[-] Error: {msg}{Style.RESET_ALL}"

def success(msg):
    return f"{Fore.GREEN}{msg}{Style.RESET_ALL}"

def delete_csv():
    """Delete all csv files inside the project folder."""

    csv_files = list(filter(lambda x: '.csv' in x, os.listdir('.')))

    for file in csv_files:
        os.remove(file) 

def reset_nic(nic):
    """Reset the wifi adapter to managed mode and start network services."""

    if not nic:
        print("No wifi adapter to reset.")
        return

    delete_csv()

    print(f"\nAttack halted.\nResetting {nic} to managed mode...", end=" ")
    subprocess.run(cmd("sudo pkill airodump-ng"))
    subprocess.run(cmd(f"airmon-ng stop {nic}"), stdout=DEVNULL)
    print(success("Done"))

    print("Restarting NIC processes...", end=" ")
    subprocess.run(cmd("sudo systemctl start wpa_supplicant NetworkManager"))
    print(success("Done.\n"))

def device_present(present, lst):
    
    for item in lst:
        if present(item):
            return True 

    return False

def get_NICs():
    """Scan for NICs using regex."""

    nic_regex = re.compile("wlan[0-9]+")

    scan_nic_cmd = subprocess.run(cmd('ifconfig'), capture_output=True).stdout.decode()

    NICs = nic_regex.findall(scan_nic_cmd)

    return NICs

def is_root():
    return 'SUDO_UID' in os.environ.keys()
