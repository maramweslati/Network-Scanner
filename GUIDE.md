# 🔐 Guide complet — Network Scanner & Security Dashboard

Ce guide te donne **toutes les étapes**, dans l'ordre, avec les explications techniques nécessaires pour comprendre *pourquoi* tu fais chaque chose (important pour un entretien où on te demandera d'expliquer ton projet).

⚠️ **Règle absolue** : ne scanne **que** ton propre réseau (ta box/routeur chez toi, ou un réseau pour lequel tu as une autorisation écrite). Scanner un réseau tiers sans autorisation est illégal en Tunisie comme ailleurs.

---

## ÉTAPE 0 — Prérequis et environnement

### 0.1 Vérifier Python
```bash
python3 --version   # il te faut Python 3.9+
```

### 0.2 Créer un environnement virtuel (bonne pratique à mettre en avant sur ton CV)
```bash
mkdir Network-Scanner && cd Network-Scanner
python3 -m venv venv
source venv/bin/activate      # Linux/Mac
# venv\Scripts\activate       # Windows
```

### 0.3 Scapy a besoin de privilèges réseau bas niveau
- **Linux/Mac** : tu devras lancer le scanner avec `sudo` (scapy envoie des trames Ethernet brutes → nécessite les capacités `CAP_NET_RAW`).
- **Windows** : tu dois installer **Npcap** (https://npcap.com/#download) avant d'installer scapy, sinon `srp()` ne fonctionnera pas. Coche "Install Npcap in WinPcap API-compatible Mode" pendant l'installation.

### 0.4 Installer les dépendances
Le fichier `requirements.txt` est fourni (voir plus bas). Installe avec :
```bash
pip install -r requirements.txt
```

### 0.5 Trouver ta plage réseau
```bash
ip addr show        # Linux : cherche ton IP locale, ex 192.168.1.42/24
ifconfig             # Mac
ipconfig              # Windows
```
Si ton IP est `192.168.1.42/24`, ta plage réseau à scanner est `192.168.1.0/24`.

---

## ÉTAPE 1 — Comprendre le protocole ARP (fondement de la V1)

Sur un réseau local (LAN), la communication au niveau 2 (Ethernet) se fait via des **adresses MAC**, pas des IP. Pour savoir "quelle MAC correspond à quelle IP", chaque machine utilise le protocole **ARP (Address Resolution Protocol)** :

1. Une machine envoie une trame **ARP Request** en broadcast (`ff:ff:ff:ff:ff:ff`) : *"Qui a l'IP 192.168.1.5 ? Dis-le-moi."*
2. La machine qui possède cette IP répond avec une **ARP Reply** contenant sa MAC.

**Astuce de scan** : si on envoie une ARP Request à *toutes* les IP possibles d'une plage (192.168.1.1 à 192.168.1.254), toutes les machines allumées vont répondre → on obtient la liste des appareils connectés, en quelques millisecondes, de façon beaucoup plus fiable qu'un ping (beaucoup de machines bloquent le ping ICMP mais ne peuvent pas ignorer une requête ARP si elles sont sur le même réseau).

C'est exactement ce que fait `scanner.py` (fourni) avec Scapy :
```python
arp = ARP(pdst=ip_range)                     # "qui a cette IP ?"
ether = Ether(dst="ff:ff:ff:ff:ff:ff")        # envoyer en broadcast Ethernet
packet = ether/arp                             # empiler les couches (Ethernet + ARP)
result = srp(packet, timeout=2, verbose=0)[0]  # envoyer et recevoir les réponses
```
`srp` = "send and receive packets at layer 2".

### Tester la V1
```bash
sudo python3 scanner.py --range 192.168.1.0/24
```
Tu dois voir une liste IP / MAC s'afficher.

---

## ÉTAPE 2 — Résolution du nom d'appareil

Chaque IP peut avoir un nom d'hôte (hostname) publié via mDNS/NetBIOS/DNS local. On essaie une résolution DNS inverse :
```python
import socket
try:
    hostname = socket.gethostbyaddr(ip)[0]
except socket.herror:
    hostname = "Inconnu"
```
Ça ne marche pas toujours (beaucoup d'appareils ne publient pas leur nom), c'est normal — dans ce cas affiche "Inconnu".

---

## ÉTAPE 3 (Version 2) — Temps de réponse (ping) et fabricant (vendor)

### 3.1 Temps de réponse
Avec scapy, tu peux mesurer le round-trip-time (RTT) directement à partir de la réponse ARP (différence de temps entre l'envoi et la réception), ou faire un ping ICMP classique avec la librairie `ping3` ou en appelant la commande système :
```python
import time
start = time.time()
# ... envoi de la requête ARP pour cette IP précise ...
rtt_ms = (time.time() - start) * 1000
```

### 3.2 Fabricant de la carte réseau (MAC Vendor / OUI)
Les 3 premiers octets d'une adresse MAC (l'**OUI**, Organizationally Unique Identifier) identifient le fabricant (Cisco, Samsung, TP-Link...). Deux approches :

**Option A — API en ligne (simple, nécessite Internet)** :
```python
import requests
def get_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        return r.text if r.status_code == 200 else "Inconnu"
    except requests.RequestException:
        return "Inconnu"
```
⚠️ Cette API a un rate-limit gratuit (~1 requête/seconde) — utile pour un usage perso, pas pour scanner 1000 appareils d'affilée.

**Option B — Base OUI locale (hors-ligne, plus pro)** :
Télécharge la base IEEE (`https://standards-oui.ieee.org/oui/oui.txt`) et fais un lookup local dans un dictionnaire `{oui: vendor}`. C'est ce que font les vrais outils comme Nmap. Je te recommande cette option pour la V2 avancée — c'est un vrai plus sur un CV ("j'ai implémenté un lookup OUI local sans dépendance API externe").

`utils.py` fourni implémente l'option A avec fallback, tu pourras évoluer vers B ensuite.

---

## ÉTAPE 4 (Version 3) — Scan de ports et détection de services

### 4.1 Principe du scan TCP Connect
Pour chaque port à tester, on essaie d'ouvrir une connexion TCP complète (le "3-way handshake" : SYN → SYN-ACK → ACK). Si ça réussit, le port est **ouvert**.
```python
import socket
def is_port_open(ip, port, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0
```
`connect_ex` retourne 0 si la connexion réussit, un code d'erreur sinon (contrairement à `connect()` qui lève une exception).

### 4.2 Pourquoi le threading est indispensable ici
Scanner les 65535 ports d'une seule IP en séquentiel, à ~0.5s de timeout chacun, prendrait **9 heures**. Avec du multithreading (ex. `ThreadPoolExecutor` à 100 threads), la même opération prend quelques secondes, car les connexions sont majoritairement en attente réseau (I/O bound) — le CPU peut gérer plusieurs sockets en parallèle.

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

### 4.3 Détection de service (banner grabbing)
Une fois un port ouvert détecté, on peut souvent lire la "bannière" que le service envoie à la connexion pour l'identifier précisément :
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
Pour un premier jet, un simple dictionnaire "port → nom de service commun" (fourni dans `utils.py`) suffit largement, et tu ajoutes le banner grabbing en bonus si tu veux impressionner.

### 4.4 Éthique / portée
Documente bien dans ton README que le scan de ports ne doit être fait **que sur des machines t'appartenant**, et limite par défaut à une liste de ports "communs" (pas les 65535) pour rester rapide et raisonnable.

---

## ÉTAPE 5 (Version 4) — Interface graphique (Tkinter)

`gui.py` (fourni) fait :
- Un tableau (`ttk.Treeview`) avec colonnes IP / Nom / MAC / Fabricant / État / Ports ouverts
- Un bouton **"Scanner"** qui lance le scan **dans un thread séparé** (`threading.Thread`) pour ne pas geler l'interface pendant les quelques secondes de scan
- Un compteur "Nombre d'appareils : X"
- Une barre de statut ("Scan en cours...", "Scan terminé")

Le point technique important à retenir (et à savoir expliquer) : **on ne doit jamais faire une opération longue (réseau, fichier, calcul) directement dans le thread principal de Tkinter**, sinon la fenêtre se fige. On lance le scan dans un thread, et on met à jour l'UI depuis ce thread via `root.after(0, callback)` pour rester thread-safe.

Pour aller plus loin (V4+), tu pourras migrer vers **PySide6** (Qt) qui est plus moderne et permet des dashboards plus soignés (graphiques, thèmes sombres, icônes par type d'appareil).

---

## ÉTAPE 6 — Organisation Git / GitHub

### 6.1 Initialiser le dépôt local
```bash
cd Network-Scanner
git init
git branch -M main
```

### 6.2 Créer `.gitignore`
```
venv/
__pycache__/
*.pyc
.DS_Store
```

### 6.3 Premier commit
```bash
git add .
git commit -m "V1: scan ARP du réseau local (IP + MAC)"
```

### 6.4 Créer le dépôt sur GitHub
Sur github.com → "New repository" → nom `Network-Scanner` → ne coche pas "Initialize with README" (tu en as déjà un) → crée.

### 6.5 Lier et pousser
```bash
git remote add origin https://github.com/TON_PSEUDO/Network-Scanner.git
git push -u origin main
```

### 6.6 Workflow recommandé (à documenter, ça montre une bonne pratique pro)
Fais un commit par version, avec des messages clairs :
```bash
git commit -m "V2: ajout ping RTT + fabricant MAC (OUI lookup)"
git commit -m "V3: scan de ports + détection de services"
git commit -m "V4: interface graphique Tkinter (dashboard)"
git push
```
Optionnel mais valorisant sur un CV : utilise des **branches** (`feature/port-scan`) et des **Pull Requests** vers `main`, même en solo — ça montre que tu maîtrises un vrai workflow Git.

---

## ÉTAPE 7 — Soigner le README

Le `README.md` fourni contient déjà : description, installation, usage, roadmap, avertissement légal. Complète-le avec :
- Un **GIF ou screenshot** du dashboard en action (utilise `LICEcap` ou `peek` pour un GIF)
- Un badge de version Python (`https://img.shields.io/badge/python-3.9+-blue`)
- Une section "Limites connues" (montre ta rigueur : ex. "ne fonctionne que sur IPv4, ne détecte pas les appareils avec ARP spoofing protection activée")

---

## ÉTAPE 8 — Idées d'évolution (pour après, si tu veux aller plus loin pour ton PFE)

- Export des résultats en CSV/JSON/PDF (génération de rapport automatique — tu as déjà cette compétence via ton labo pentest)
- Alertes : détecter un **nouvel appareil** inconnu apparaissant sur le réseau (petit moteur de détection d'anomalie simple, base pour un futur mini-IDS)
- Sauvegarde historique des scans dans SQLite (tu as déjà cette compétence via ton lab Android SQLite)
- Passage à PySide6 pour un dashboard plus pro avec graphiques (nombre d'appareils dans le temps)
- Version suivante logique : mini-IDS qui surveille le trafic ARP en continu pour détecter de l'**ARP spoofing** (attaque très classique, en lien direct avec ton cours réseau-sécurité)

---

## Dépannage courant

| Problème | Cause probable | Solution |
|---|---|---|
| `PermissionError` sur `srp()` | Pas de droits root | Lance avec `sudo` |
| Scapy ne trouve aucun appareil | Mauvaise interface réseau sélectionnée | Précise l'interface avec `iface="eth0"` dans `srp()` |
| Aucun résultat sous Windows | Npcap non installé | Installer Npcap en mode compatible WinPcap |
| `requests.exceptions.Timeout` sur le vendor lookup | API macvendors.com rate-limitée | Ajoute un `time.sleep(1)` entre appels ou passe à la base OUI locale |
| L'interface Tkinter se fige pendant le scan | Scan lancé dans le thread principal | Vérifie que le scan tourne bien dans un `threading.Thread` (voir gui.py) |
