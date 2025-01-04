from scapy.all import Ether, IP, sendp, sniff, Raw, ARP 
from time import sleep
from datetime import datetime
from threading import Thread
from random import choice
from subprocess import run, PIPE
from requests import get
import sys
import dns.resolver


# ask some question about cluster
ask_for_services_name = input('which services is run on servers?None/DNS/Web/both:').lower()
url = ''
domain = ''
# ask for exists services information
if ask_for_services_name == 'none':
    print('script handles only server failure.')
elif ask_for_services_name == 'web':
    url = input('please enter the url:')
elif ask_for_services_name == 'dns':
    domain = input('please enter the domain-name:')
elif ask_for_services_name == 'both':
    url = input('please enter the url:')
    domain = input('please enter the domain-name:')

NIC = input("please enter the NIC name that connected to other devices:")
how_many_devices_in_cluster = int(input("please enter the number of devices that should be in a cluster:"))
virtual_ip = input("please enter the Virtual IP-Address:")
priority = input("please enter this devices priority:")


# we should collect devices information in a central point
devices_information_list = []
failed_devices_mac_address_list = []
active_devices_mac_address_list = []
mapped_vnic_to_failed_mac_list = []
AVG_status_of_this_device = False
AVG_device_ip_address = ''
AVG_failure = False



# create keepalive message
frame = Ether(dst='ff:ff:ff:ff:ff:ff',type=0x0800)
packet = IP(dst= '239.0.0.1')
hello_message = frame/packet/Raw(load = priority)

# create virtual NIC to device, accept the traffics that send to virtual IP-Address
def vNIC():
    global virtual_ip
    costumize_command = 'ip addr add '+virtual_ip+' dev br100'
    commands = ['ip link delete br100','ip link add name br100 type bridge','ip link set eth100 master br100',costumize_command,'ip link set br100 up', 'ip link set eth100 up', 'ip link set dev br100 arp off']
    for command in commands:
        result = run(command, shell=True, capture_output= True)


# create function to send hello message in 3s interval 
def hello_message_sender():
    global NIC
    while True:
        sendp(hello_message, iface= NIC, verbose= False)
        sleep(3)
        
# create function to sniff hello messages
def hello_message_sniffer():
    print('searching for devices...')
    global NIC
    global devices_information_list
    global active_devices_mac_address_list
    information_dictinary = {
        'device_ip' : '',
        'device_mac' : '',
        'device_priority' : '',
        'AVG_status': False,
        'device_status':'UP'
    }
    detected_devices = []
    while True:
        sniffed_packet = sniff(iface = NIC, filter = 'dst host 239.0.0.1', count = 1)
        if sniffed_packet[0][1].src not in detected_devices:
            # add devices ip to detected device list, to prevent from repeated detction 
            detected_devices.append(sniffed_packet[0][1].src)
            print(f"new device detected in cluster=>{sniffed_packet[0][1].src}")
            # add information of detected device
            information_dictinary['device_ip'] = sniffed_packet[0][1].src
            information_dictinary['device_mac'] = sniffed_packet[0][0].src
            information_dictinary['device_priority'] = sniffed_packet[0][2].load.decode()
            # append information dictionary of detected device in devices_information_list
            devices_information_list.append(information_dictinary.copy())
            # completing the active_devices_mac_address_list
            active_devices_mac_address_list.append(sniffed_packet[0][0].src)
        if len(detected_devices) == int(how_many_devices_in_cluster):
            print("All devices detect!")
            break 
        


# create function to detect the AVG device
def AVG_selection():
    # calling the global functions
    global devices_information_list
    global priority
    global AVG_status_of_this_device
    global AVG_device_ip_address
    highest_priority = '0'
    for device in devices_information_list:
        if int(device['device_priority']) >= int(highest_priority):
            highest_priority = device['device_priority']
    # announcement the AVG device and update th AVG-status of AVG device in devices list
    for device in devices_information_list:
        if str(highest_priority) in device['device_priority']:
            device['AVG_status'] = True
            if int(highest_priority) == int(priority):
                AVG_status_of_this_device = True
                AVG_device_ip_address = device["device_ip"]
                print('This device is new AVG!')
            else:
                AVG_device_ip_address = device["device_ip"]
                print(f'The new AVG device is > {device["device_ip"]}')

# the AVG should handle the failed servers mac-address for 1 day                
def handle_the_failed_AVF_MAC():
    global AVG_status_of_this_device
    global how_many_devices_in_cluster
    global failed_devices_mac_address_list
    global mapped_vnic_to_failed_mac_list
    mapping_vnic_to_failed_mac = {
        "interface_name" : '',
        "mapped_mac": '',
        "time_stamp":''
    }

    used_interface_list=[]
    # we should check the dummy interface name, to if that name exists, create dummy with other name
    interface_number = 1
    if AVG_status_of_this_device == True:
        
        if len(failed_devices_mac_address_list) !=0:
            if len(mapped_vnic_to_failed_mac_list) == 0 :
                for mac in failed_devices_mac_address_list:
                    mapping_vnic_to_failed_mac['interface_name'] = "dummy"+str(interface_number)
                    mapping_vnic_to_failed_mac['mapped_mac'] = mac
                    mapping_vnic_to_failed_mac['time_stamp'] = datetime.now()
                    mapped_vnic_to_failed_mac_list.append(mapping_vnic_to_failed_mac.copy())
            else:
                for mac in failed_devices_mac_address_list:
                    for entity in mapped_vnic_to_failed_mac_list:
                        if mac != entity['mapped_mac']:
                            mapping_vnic_to_failed_mac['interface_name'] = "dummy"+str(interface_number)
                            mapping_vnic_to_failed_mac['mapped_mac'] = mac
                            mapping_vnic_to_failed_mac['time_stamp'] = datetime.now()
                            mapping_vnic_to_failed_mac.append(mapping_vnic_to_failed_mac.copy())
                
            # create dummy interfaces        
            commands = ['ip link delete '+mapping_vnic_to_failed_mac['interface_name'],'ip link add name '+mapping_vnic_to_failed_mac['interface_name']+' type dummy', 'ip link set dev '+mapping_vnic_to_failed_mac['interface_name']+' up', 'ip link set dev '+mapping_vnic_to_failed_mac['interface_name']+' address '+mapping_vnic_to_failed_mac['mapped_mac']]
            for command in commands:
                result = run(command, shell=True, capture_output= True)
                        
        # delete the virtual NIC, if the AVF backed up
        if len(failed_devices_mac_address_list) == 0:
            for interface in mapped_vnic_to_failed_mac_list:
                current_interface = interface['interface_name']
                deleting_NIC_command = 'ip link delete '+ current_interface
                execute_recover_command = run(deleting_NIC_command, shell=True, capture_output=True)
                
        else:
            for mac in failed_devices_mac_address_list:
                for entity in mapped_vnic_to_failed_mac_list:
                    if mac == entity['mapped_mac']:
                        continue
                    else:
                        deleting_NIC_command = 'ip link delete '+entity['interface_name']
                        execute_recover_command = run(deleting_NIC_command, shell=True, capture_output=True)
                       
 # this function check the vnic list in 1h interval, if any vnic created, should removes after 1D 
def deleting_VNIC():
    global mapped_vnic_to_failed_mac_list
    while True:
        if len(mapped_vnic_to_failed_mac_list) != 0:
            current_time = datetime.now()
            for member in mapped_vnic_to_failed_mac_list:
                if (current_time - member['time_stamp']).days > 1:
                    command_for_deleting_NIC = 'ip link delete ' + member['interface_name']
                    execute_deleting_command = run(command_for_deleting_NIC, shell=True, capture_output=True)
                    sleep(3600)
                    
        else:
            sleep(3600)     
            

            


# create the track function to track other devices based on this devices AVG-status
def Track_devices():
    # calling the global functions
    global NIC
    global AVG_status_of_this_device
    global devices_information_list
    global failed_devices_mac_address_list
    global AVG_device_ip_address
    global AVG_failure
    AVG_reliebility_cheking = 0 
    AVF_reliebility_cheking = 0
    previous_AVG = AVG_device_ip_address
    # if this device operations as AVG, it should track all other devices 
    if AVG_status_of_this_device == True:
        while True:
            for device in devices_information_list: 
                condition = 'src host '+device['device_ip']+' and dst host 239.0.0.1'
                received_packet_of_device = sniff(iface = NIC, filter = condition, timeout = 20, count = 1)
                if len(received_packet_of_device) != 0:
                    sleep(5)
                    
                elif len(received_packet_of_device) == 0:
                    print(f"The <{device['device_ip']}> is failed!")
                    device["device_status"] = 'Down'
                    if device['device_mac'] not in failed_devices_mac_address_list:
                        failed_devices_mac_address_list.append(device['device_mac'])
                    if device['device_mac'] in active_devices_mac_address_list:
                        active_devices_mac_address_list.remove(device['device_mac'])
                    handle_the_failed_AVF_MAC()
                    
                    
                    # start tracking the failed device
                    while device["device_status"] == 'Down':
                        print(f'Tracking the<{device["device_ip"]}>..')
                        condition_2 = 'src host '+device["device_ip"]+' and dst host 239.0.0.1'
                        track_failed_AVF = sniff(iface = NIC, filter = condition_2, timeout = 10, count = 1)
                        if len(track_failed_AVF) == 0:
                            device["device_status"] == 'Down'
                        elif len(track_failed_AVF) != 0:
                            for i in range(3):
                                if len(track_failed_AVF) != 0:
                                    AVF_reliebility_cheking +=10
                                    sleep(10)
                                    if AVF_reliebility_cheking == 30:
                                        print(f'The<{device["device_ip"]}> recoverd')
                                        if device['device_mac'] in failed_devices_mac_address_list:
                                            failed_devices_mac_address_list.remove(device['device_mac'])
                                        if device['device_mac'] not in active_devices_mac_address_list:
                                            active_devices_mac_address_list.append(device['device_mac'])
                                        filter_condition = "src host " + device["device_ip"] + " and dst host 239.0.0.1"
                                        sniff_new_priority = sniff(iface = NIC, filter = filter_condition, count = 1)
                                        device['device_priority'] = sniff_new_priority[0][2].load.decode()
                                        device["device_status"] = 'UP'
                                        handle_the_failed_AVF_MAC()
                                        AVG_selection()
                        
    # this condition works when the current device doesnt AVG, so it should track the AVG
    if AVG_status_of_this_device == False:
        while True:
            condition = 'src host '+AVG_device_ip_address+' and dst host 239.0.0.1'
            received_packet_of_device = sniff(iface = NIC, filter = condition, timeout = 20, count = 1)
            
            if len(received_packet_of_device) != 0:
                AVG_reliebility_cheking = 0 
                AVG_failure =False
                sleep(5)

            elif len(received_packet_of_device) == 0:
                AVG_failure = True
                print("The AVG is failed!!")
                print("re-selection the AVG device...")
                # modifying the devices information list and changing the priority and AVG-status
                for device in devices_information_list:
                    if device['device_ip'] == AVG_device_ip_address:
                        device['AVG-status'] = False
                        device['device_priority'] = '0'
                AVG_selection()
                # updating the failed and active devices mac-address
                if device['device_mac'] not in failed_devices_mac_address_list:
                    failed_devices_mac_address_list.append(device['device_mac'])
                if device['device_mac'] in active_devices_mac_address_list:
                    active_devices_mac_address_list.remove(device['device_mac'])
           # track the previous AVG to when it back again, selected as AVG        
                while AVG_failure == True:
                    print("Tracking the previous AVG...")
                    # The device should selected as AVG again if it can pass the reliebility cheker test
                    condition_2 = 'src host '+previous_AVG+' and dst host 239.0.0.1'
                    track_previous_AVG = sniff(iface = NIC, filter = condition_2, timeout = 10, count = 1)
                    for i in range(3):
                        if len(track_previous_AVG) != 0:
                            AVG_reliebility_cheking +=10
                            sleep(10)
                            if AVG_reliebility_cheking == 30:
                                for device in devices_information_list:
                                        if device['device_ip'] == previous_AVG:
                                            device['AVG-status'] = False
                                            device['device_priority'] = track_previous_AVG[0][2].load.decode()
                                AVG_selection()
                                if device['device_mac'] in failed_devices_mac_address_list:
                                    failed_devices_mac_address_list.remove(device['device_mac'])
                                if device['device_mac'] not in active_devices_mac_address_list:
                                    active_devices_mac_address_list.append(device['device_mac'])
                                AVG_failure = False
                                print('the previos AVG is recoverd!!!!')
                                
                
                


# create function for loadbalancing by random library
def load_balance():
    global active_devices_mac_address_list
    return choice(active_devices_mac_address_list)

# handeling the ARP_Requests sent from clients to VIP
def ARP_Reply():
    global AVG_status_of_this_device
    global virtual_ip
    global NIC
    if AVG_status_of_this_device == True:
        def arp_request(packet):
            if packet[ARP].pdst == virtual_ip and packet[ARP].op == 1:
                arp_reply = packet
                arp_reply[0][0].dst = arp_reply[0][0].src
                arp_reply[0][0].src = load_balance()
                arp_reply[0][1].hwdst = arp_reply[0][1].hwsrc
                arp_reply[0][1].pdst = arp_reply[0][1].psrc
                arp_reply[0][1].hwsrc = load_balance()
                arp_reply[0][1].psrc = virtual_ip
                sendp(arp_reply, iface=NIC, count = 3, verbose = False)

        while True:
            sniff(iface= NIC, filter = "arp", prn = arp_request, store = 0)


def track_services():
    global domain
    global url
    # track only web-service
    if url != '' and domain == '':
        while True:
            response = get(url)
            if response.status_code == 200:
                sleep(60)
            else:
                sleep(20)
                response = get(url)
                if response.status_code !=200:
                    sys.exit()
        

    # track only dns 
    if domain != '' and url == '':
        while True:
            result = dns.resolver.resolve(domain, 'A')
            if domain in result:
                    sleep(60)
            else:
                sleep(20)
                result = dns.resolver.resolve(domain, 'A')
                if domain not in result:
                    sys.exit()
                
    # track both web service and dns service
    if domain != '' and url == '':
        while True:
            result = dns.resolver.resolve(domain, 'A')
            response = get(url)

            if response.status_code == 200 and domain in result:
                sleep(60)
            elif response.status_code!=200:
                sleep(20)
                response = get(url)
                if response.status_code !=200:
                    sys.exit()    
            elif domain not in result:
                sleep(20)
                result = dns.resolver.resolve(domain, 'A')
                if domain not in result:
                    sys.exit()     




vNIC_thread = Thread(target=vNIC)
hello_message_sender_thread = Thread(target=hello_message_sender)
hello_message_sniffer_thread = Thread(target=hello_message_sniffer)
AVG_selection_thread = Thread(target=AVG_selection)
Track_devices_thread = Thread(target=Track_devices)
ARP_Reply_thread = Thread(target=ARP_Reply)
track_services_thread = Thread(target=track_services)
handle_the_failed_AVF_MAC_Thread = Thread(target=handle_the_failed_AVF_MAC)
deleting_VNIC_thread = Thread(target=deleting_VNIC)
vNIC_thread.start()
vNIC_thread.join()
hello_message_sender_thread.start()
hello_message_sniffer_thread.start()
hello_message_sniffer_thread.join()
AVG_selection_thread.start()
AVG_selection_thread.join()
Track_devices_thread.start()
ARP_Reply_thread.start()
track_services_thread.start()
handle_the_failed_AVF_MAC_Thread.start()
deleting_VNIC_thread.start()





    