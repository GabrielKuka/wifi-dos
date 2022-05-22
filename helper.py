from asyncio.subprocess import DEVNULL
import subprocess, os, re 

def cmd(cmd):
    return cmd.split(' ')

def delete_csv():
    csv_files = list(filter(lambda x: '.csv' in x, os.listdir('.')))

    for file in csv_files:
        os.remove(file) 

def reset_nic(nic):
    if not nic:
        print("No wifi adapter to reset.")
        return

    delete_csv()

    print(f"\nAttack halted.\nResetting {nic} to managed mode...", end=" ")
    subprocess.run(cmd("sudo pkill airodump-ng"))
    subprocess.run(cmd(f"airmon-ng stop {nic}"), stdout=DEVNULL)
    print("Done.")

    print("Restarting NIC processes...", end=" ")
    subprocess.run(cmd("sudo systemctl start wpa_supplicant NetworkManager"))
    print("Done.\n")

def ap_present(essid, lst):

    for item in lst:
        if essid in item["ESSID"]:
            return True

    return False 

def get_NICs():
    nic_regex = re.compile("wlan[0-9]+")

    scan_nic_cmd = subprocess.run(cmd('ifconfig'), capture_output=True).stdout.decode()

    NICs = nic_regex.findall(scan_nic_cmd)

    return NICs

def is_root():
    return 'SUDO_UID' in os.environ.keys()
