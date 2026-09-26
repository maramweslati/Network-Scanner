# Guide technique — Network Scanner & Security Dashboard

Ce document décrit les étapes de mise en place, le fonctionnement interne des différents modules, ainsi que les choix techniques du projet.

Avertissement : l'utilisation de cet outil doit être limitée à des réseaux pour lesquels une autorisation explicite existe (réseau personnel ou réseau couvert par une autorisation écrite). Le scan d'un réseau tiers sans autorisation est illégal.

---

## 1. Prérequis et environnement

### 1.1 Version de Python requise

```bash
python3 --version
```

Python 3.9 ou supérieur est requis.

### 1.2 Environnement virtuel

L'utilisation d'un environnement virtuel isole les dépendances du projet de l'installation système.

```bash
mkdir Network-Scanner && cd Network-Scanner
python3 -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
```

### 1.3 Privilèges réseau requis par Scapy

Scapy nécessite un accès bas niveau à la carte réseau pour la construction et l'envoi de trames.

- Linux/Mac : le script doit être exécuté avec `sudo`, car l'envoi de trames Ethernet brutes requiert la capacité `CAP_NET_RAW`.
- Windows : Npcap doit être installé avant l'installation de Scapy, faute de quoi la fonction `srp()` ne fonctionne pas. L'option "Install Npcap in WinPcap API-compatible Mode" doit être activée durant l'installation.

### 1.4 Installation des dépendances

```bash
pip install -r requirements.txt
```

### 1.5 Identification de la plage réseau locale

```bash
ip addr show        # Linux
ifconfig             # Mac
ipconfig              # Windows
```

Pour une IP locale de type `192.168.1.42/24`, la plage réseau correspondante est `192.168.1.0/24`.

---

## 2. Découverte des hôtes via ARP

Sur un réseau local, la résolution entre adresse IP et adresse MAC repose sur le protocole ARP (Address Resolution Protocol) :

1. Une requête ARP est envoyée en broadcast (`ff:ff:ff:ff:ff:ff`), demandant quelle machine possède une IP donnée.
2. La machine correspondante répond avec sa propre adresse MAC.

En envoyant une requête ARP à l'ensemble des adresses IP d'une plage réseau, l'ensemble des hôtes actifs peut être identifié en quelques millisecondes. Cette méthode est plus fiable qu'un scan ICMP classique, dans la mesure où de nombreux hôtes bloquent le ping mais ne peuvent pas ignorer une requête ARP provenant du même segment réseau.

Implémentation dans `scanner.py` :

```python
arp = ARP(pdst=ip_range)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp
result = srp(packet, timeout=2, verbose=0)[0]
```

`srp` (send and receive packets) envoie les trames construites au niveau 2 et collecte les réponses.

Exécution :

```bash
sudo python3 scanner.py --range 192.168.1.0/24
```

Le résultat attendu est une liste des couples IP / adresse MAC des hôtes actifs du réseau.

---

## 3. Résolution du nom d'hôte

Une résolution DNS inverse est tentée pour chaque IP détectée :

```python
import socket
try:
    hostname = socket.gethostbyaddr(ip)[0]
except socket.herror:
    hostname = "Inconnu"
```

Cette résolution échoue fréquemment, la plupart des appareils ne publiant pas de nom d'hôte résolvable localement ; dans ce cas, la valeur "Inconnu" est utilisée.

---

## 4. Temps de réponse et identification du fabricant

### 4.1 Temps de réponse (RTT)

Le round-trip-time peut être mesuré à partir de la différence entre l'envoi de la requête ARP et la réception de la réponse :

```python
import time
start = time.time()
# envoi de la requête ARP pour l'IP concernée
rtt_ms = (time.time() - start) * 1000
```

### 4.2 Identification du fabricant (OUI)

Les trois premiers octets d'une adresse MAC constituent l'OUI (Organizationally Unique Identifier), qui identifie le fabricant de l'interface réseau.

Option A — requête vers une API externe :

```python
import requests
def get_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        return r.text if r.status_code == 200 else "Inconnu"
    except requests.RequestException:
        return "Inconnu"
```

Cette API impose une limite de débit d'environ une requête par seconde en usage gratuit, ce qui la rend inadaptée à un scan de grande échelle.

Option B — base OUI locale : la base IEEE (`https://standards-oui.ieee.org/oui/oui.txt`) peut être téléchargée et utilisée pour un lookup hors-ligne, à la manière des outils de référence tels que Nmap. Cette approche est recommandée pour une version avancée du projet, dans la mesure où elle supprime la dépendance à un service externe.

`utils.py` implémente l'option A avec repli sur "Inconnu" en cas d'échec.

---

## 5. Scan de ports et détection de services

### 5.1 Principe du scan TCP Connect

Pour chaque port testé, une connexion TCP complète est tentée (three-way handshake : SYN, SYN-ACK, ACK). Une connexion réussie indique un port ouvert.

```python
import socket
def is_port_open(ip, port, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0
```

`connect_ex` retourne 0 en cas de succès et un code d'erreur en cas d'échec, sans lever d'exception.

### 5.2 Justification du multithreading

Un scan séquentiel de l'ensemble des 65535 ports d'une IP, avec un timeout de 0.5 seconde, nécessiterait environ neuf heures. L'opération étant majoritairement liée aux entrées-sorties réseau (I/O bound) plutôt qu'au calcul, un parallélisme via `ThreadPoolExecutor` permet de réduire cette durée à quelques secondes.

```python
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}

def scan_ports(ip, ports=COMMON_PORTS.keys(), max_workers=50):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(lambda p: (p, is_port_open(ip, p)), ports)
    for port, is_open in results:
        if is_open:
            open_ports.append(port)
    return open_ports
```

### 5.3 Identification de service (banner grabbing)

Lorsqu'un port ouvert est détecté, la bannière renvoyée par le service à la connexion permet souvent de l'identifier précisément :

```python
def grab_banner(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return s.recv(1024).decode(errors="ignore").strip()
    except Exception:
        return ""
```

Un dictionnaire associant chaque port courant à un nom de service (fourni dans `utils.py`) constitue une base suffisante ; le banner grabbing peut être ajouté en complément.

### 5.4 Portée du scan

Le scan de ports doit être limité aux machines appartenant à l'utilisateur, et restreint par défaut à une liste de ports courants plutôt qu'à l'ensemble des 65535 ports, afin de rester rapide et raisonnable.

---

## 6. Interface graphique (Tkinter)

`gui.py` fournit :

- un tableau (`ttk.Treeview`) avec les colonnes IP, nom, adresse MAC, fabricant, état, ports ouverts
- un bouton de lancement du scan, exécuté dans un thread séparé (`threading.Thread`) afin de ne pas bloquer l'interface pendant l'exécution
- un compteur d'appareils détectés
- une barre de statut indiquant l'état du scan

Une opération longue (réseau, fichier, calcul) ne doit jamais être exécutée dans le thread principal de Tkinter, sous peine de figer l'interface. Le scan est donc exécuté dans un thread dédié, et la mise à jour de l'interface depuis ce thread est effectuée via `root.after(0, callback)` pour rester thread-safe.

Une migration vers PySide6 (Qt) constitue une évolution possible pour un dashboard plus élaboré (graphiques, thèmes, icônes par type d'appareil).

---

## 7. Organisation du dépôt Git

### 7.1 Initialisation

```bash
cd Network-Scanner
git init
git branch -M main
```

### 7.2 Fichier .gitignore

```
venv/
__pycache__/
*.pyc
.DS_Store
```

### 7.3 Premier commit

```bash
git add .
git commit -m "V1: scan ARP du reseau local (IP + MAC)"
```

### 7.4 Création du dépôt distant

Sur GitHub, un nouveau dépôt est créé sans initialisation de README, un README étant déjà présent localement.

### 7.5 Liaison et publication

```bash
git remote add origin https://github.com/<utilisateur>/Network-Scanner.git
git push -u origin main
```

### 7.6 Convention de commits

Un commit par version, avec un message décrivant le contenu ajouté :

```bash
git commit -m "V2: ajout RTT et identification du fabricant (OUI)"
git commit -m "V3: scan de ports et detection de services"
git commit -m "V4: interface graphique Tkinter"
git push
```

L'utilisation de branches (`feature/port-scan`) et de pull requests vers `main`, même en développement individuel, reflète un usage professionnel de Git.

---

## 8. Évolutions possibles

- Export des résultats en CSV, JSON ou PDF
- Détection d'un nouvel appareil apparaissant sur le réseau
- Historisation des scans dans une base SQLite
- Migration vers PySide6 pour un dashboard avec graphiques
- Surveillance continue du trafic ARP pour la détection d'ARP spoofing

---

## 9. Dépannage

| Problème | Cause probable | Solution |
|---|---|---|
| `PermissionError` sur `srp()` | Absence de droits root | Exécuter avec `sudo` |
| Aucun appareil détecté | Interface réseau incorrecte | Préciser l'interface via `iface="eth0"` dans `srp()` |
| Aucun résultat sous Windows | Npcap non installé | Installer Npcap en mode compatible WinPcap |
| `requests.exceptions.Timeout` sur la recherche de fabricant | Limitation de débit de l'API macvendors.com | Ajouter un délai entre les appels ou utiliser une base OUI locale |
| Interface Tkinter figée pendant le scan | Scan exécuté dans le thread principal | Vérifier que le scan s'exécute dans un `threading.Thread` (voir gui.py) |
