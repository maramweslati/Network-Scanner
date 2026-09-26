"""
utils.py
Fonctions utilitaires : résolution de nom, fabricant MAC, ping RTT,
scan de ports et détection de services communs.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor

import requests

# Ports les plus fréquents à scanner par défaut (V3)
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


def resolve_hostname(ip: str) -> str:
    """Tente une résolution DNS inverse. Retourne 'Inconnu' si impossible."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Inconnu"


def get_vendor(mac: str) -> str:
    """
    Récupère le fabricant de la carte réseau à partir de l'adresse MAC
    via l'API publique macvendors.com (limité en requêtes/seconde).
    """
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            return response.text.strip()
        return "Inconnu"
    except requests.RequestException:
        return "Inconnu"


def measure_rtt(ip: str, timeout: float = 1.0) -> float | None:
    """
    Mesure un temps de réponse approximatif en tentant une connexion TCP
    sur le port 80 (fallback simple sans dépendre d'ICMP qui nécessite
    souvent des privilèges root selon l'OS). Retourne le RTT en ms ou None.
    """
    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect_ex((ip, 80))
        return round((time.time() - start) * 1000, 1)
    except OSError:
        return None


def is_port_open(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Teste si un port TCP est ouvert via un connect() complet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """Essaie de lire la bannière renvoyée par un service pour l'identifier."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return s.recv(1024).decode(errors="ignore").strip()
    except OSError:
        return ""


def scan_ports(ip: str, ports: dict = COMMON_PORTS, max_workers: int = 30) -> list[dict]:
    """
    Scanne une liste de ports en parallèle (threading) et retourne
    la liste des ports ouverts avec le service probable associé.
    """
    open_ports = []

    def check(port_service):
        port, service_name = port_service
        if is_port_open(ip, port):
            return {"port": port, "service": service_name}
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(check, ports.items())

    for result in results:
        if result:
            open_ports.append(result)

    return open_ports
