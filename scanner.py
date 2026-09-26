"""
scanner.py
Coeur du Network Scanner : découverte des appareils sur le réseau local
via une requête ARP broadcast, puis enrichissement des résultats
(nom d'hôte, fabricant, RTT, ports ouverts).

Usage :
    sudo python3 scanner.py --range 192.168.1.0/24
    sudo python3 scanner.py --range 192.168.1.0/24 --ports
"""

import argparse
import time

from scapy.all import ARP, Ether, srp

from utils import resolve_hostname, get_vendor, measure_rtt, scan_ports


def scan_network(ip_range: str, timeout: int = 2) -> list[dict]:
    """
    Envoie une requête ARP broadcast sur toute la plage IP donnée
    et retourne la liste des appareils qui ont répondu (donc allumés
    et présents sur le réseau local).
    """
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=timeout, verbose=0)

    devices = []
    for _sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices


def enrich_device(device: dict, do_port_scan: bool = False) -> dict:
    """Ajoute nom d'hôte, fabricant, RTT et (optionnel) ports ouverts."""
    device["hostname"] = resolve_hostname(device["ip"])
    device["vendor"] = get_vendor(device["mac"])
    device["rtt_ms"] = measure_rtt(device["ip"])
    device["state"] = "Online" if device["rtt_ms"] is not None else "Online (ARP)"

    if do_port_scan:
        device["open_ports"] = scan_ports(device["ip"])
    else:
        device["open_ports"] = []

    return device


def run_scan(ip_range: str, do_port_scan: bool = False) -> list[dict]:
    """Point d'entrée principal : scan + enrichissement de chaque appareil."""
    print(f"[+] Scan ARP sur {ip_range} en cours...")
    start = time.time()

    devices = scan_network(ip_range)
    print(f"[+] {len(devices)} appareil(s) détecté(s) en {time.time() - start:.2f}s")

    enriched = [enrich_device(d, do_port_scan) for d in devices]
    return enriched


def print_results(devices: list[dict]) -> None:
    print("\nNetwork Scanner")
    print(f"Nombre d'appareils : {len(devices)}")
    print("-" * 70)
    print(f"{'IP':<16}{'MAC':<20}{'Nom':<15}{'Etat':<10}")
    print("-" * 70)
    for d in devices:
        print(f"{d['ip']:<16}{d['mac']:<20}{d['hostname']:<15}{d['state']:<10}")
        if d["open_ports"]:
            ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in d["open_ports"])
            print(f"   └─ Ports ouverts : {ports_str}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Scanner & Security Dashboard")
    parser.add_argument(
        "--range", default="192.168.1.0/24",
        help="Plage réseau à scanner (ex: 192.168.1.0/24)"
    )
    parser.add_argument(
        "--ports", action="store_true",
        help="Active le scan de ports (V3, plus lent)"
    )
    args = parser.parse_args()

    results = run_scan(args.range, do_port_scan=args.ports)
    print_results(results)
