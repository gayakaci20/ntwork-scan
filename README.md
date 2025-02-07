# 🔍 Network Scanner Tool  

Un outil de **scan réseau** complet permettant de **découvrir les appareils connectés**, **analyser les ports**, et **effectuer des vérifications de vulnérabilités**.  

## ✨ Fonctionnalités  

✅ **Découverte des appareils** via **ARP** ou **PING scan**  
✅ **Scan des ports** avec **détection des services** 🔌  
✅ **Analyse basique des vulnérabilités** 🔒  
✅ **Génération de rapports JSON** 📄  

## 📌 Prérequis  

🐍 **Python** 3.6 ou supérieur  
🛠️ **nmap** (Network Mapper)  

### 📥 Installation de nmap  

- **Ubuntu/Debian** : `sudo apt-get install nmap`  
- **macOS** : `brew install nmap`  
- **Windows** : Télécharger depuis [nmap.org](https://nmap.org/download.html)  

## ⚙️ Installation  

1️⃣ **Cloner le repository** 🔽  
```bash
git clone <repository-url>
cd network-scan
```

2️⃣ **Installer le package** 📦  
```bash
pip install .
```
Ou en mode développement :  
```bash
pip install -e .
```

## 🚀 Utilisation  

```bash
network-scan -t TARGET [-s SCAN_TYPE] [-p PORT_RANGE] [-o OUTPUT_FILE] [-f FORMAT]
```

📌 **Arguments** :  
- `-t, --target` : **Réseau cible** ou **IP range** (ex: `"192.168.1.0/24"`)  
- `-s, --scan_type` : **Type de scan** ("arp" ou "ping", **défaut**: "arp")  
- `-p, --port_range` : **Plage de ports** à scanner (**défaut**: "1-1024")  
- `-o, --output` : **Fichier de sortie** (**défaut**: "report.json")  
- `-f, --format` : **Format de sortie** (**actuellement supporté** : "json")  

📌 **Exemple** :  
```bash
network-scan -t 192.168.1.0/24 -s arp -p 1-100 -o network_scan.json
```

## ⚠️ Remarque  

Certaines fonctionnalités nécessitent **les privilèges root/administrateur** :  
🔹 **Scan ARP**  
🔹 **Scan PING**  
🔹 **Scan des ports**  

💡 **Exécuter avec sudo/administrateur si nécessaire** :  
```bash
sudo network-scan -t 192.168.1.0/24
```
