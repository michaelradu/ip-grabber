from scapy.all import *
import requests
import time

# Only use this in Apps that are Peer to Peer like Omegle and not Client-Server model apps
def get_ip(pkt):
    try:
        ip = pkt[IP].src
        """ Check that you aren't getting your own IP
            type in the first 3 digits of your private IP
        """
        if ip[:4] == "192.":
            return
        req = requests.get(f"http://ipapi.co/{ip}/json/").json()
        printf(f"""
        IP: {req.get('ip')}
        Country: {req.get('country_name')}
        City: {req.get('city')}
        Region: {req.get('region')}
        ISP: {req.get('org')}
        {'-'*20}""")
    except:
        print("Error, couldn't get Packet information")
        return
while True:
    """
    UDP is usually more common than TCP in online P2P chatting platforms
    Filter for the UDP protocol, pass the datagram to the get_ip function
    and sniff only 1 datagram/packet every 4s
    """
    sniff(filter="UDP", prn=get_ip, count=1)
    time.sleep(4)
