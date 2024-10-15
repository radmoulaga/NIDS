from scapy.all import sniff, TCP, IP, ARP
from collections import Counter
import time

# Détection de signature : Scan SYN
def detecter_scan_syn(packet):
    if TCP in packet and packet[TCP].flags == 'S':  # Flag SYN détecté
        src_ip = packet[IP].src
        print(f"Scan SYN détecté depuis l'IP {src_ip}")

# Détection d'anomalies : Volume de trafic
volume_trafic = Counter()
def compter_paquets(packet):
    if IP in packet:  # S'assurer que le paquet contient une adresse IP
        src_ip = packet[IP].src
        volume_trafic[src_ip] += 1  # Incrémenter le compteur pour chaque IP

def afficher_volume():
    for src_ip, count in volume_trafic.items():
        if count > 100:  # Seuil arbitraire pour définir un volume de trafic anormal
            print(f"Activité anormale détectée : {src_ip} a envoyé {count} paquets")

# Table ARP pour stocker les associations IP/MAC
arp_table = {}

# Détection d'ARP Spoofing
def detecter_arp_spoofing(packet):
    if ARP in packet and packet[ARP].op == 2:  # Réponse ARP détectée
        ip_src = packet[ARP].psrc
        mac_src = packet[ARP].hwsrc

        if ip_src in arp_table:
            if arp_table[ip_src] != mac_src:
                print(f"[ALERTE] ARP Spoofing détecté : {ip_src} a changé de {arp_table[ip_src]} à {mac_src} !")
        else:
            arp_table[ip_src] = mac_src

# Fonction principale pour le NIDS
def nids():
    # Capture des paquets avec un timeout de 10 secondes
    print("Capture des paquets en cours...")
   
