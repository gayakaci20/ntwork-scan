# 🔍 Network Scanner Tool  

A **comprehensive network scanning tool** that allows you to **discover connected devices**, **analyze ports**, and **perform basic vulnerability checks**.  

## ✨ Features  

✅ **Device discovery** via **ARP** or **PING scan**  
✅ **Port scanning** with **service detection** 🔌  
✅ **Basic vulnerability analysis** 🔒  
✅ **JSON report generation** 📄  

## 📌 Prerequisites  

🐍 **Python** 3.6 or higher  
🛠️ **nmap** (Network Mapper)  

### 📥 Installing nmap  

- **Ubuntu/Debian**: `sudo apt-get install nmap`  
- **macOS**: `brew install nmap`  
- **Windows**: Download from [nmap.org](https://nmap.org/download.html)  

## ⚙️ Installation  

1️⃣ **Clone the repository** 🔽  
```bash
git clone https://github.com/gayakaci20/ntwork-scan.git
cd network-scan
```

2️⃣ **Install the package** 📦  
```bash
pip install .
```
Or in development mode:  
```bash
pip install -e .
```

## 🚀 Usage  

```bash
network-scan -t TARGET [-s SCAN_TYPE] [-p PORT_RANGE] [-o OUTPUT_FILE] [-f FORMAT]
```

📌 **Arguments**:  
- `-t, --target`: **Target network** or **IP range** (e.g., `"192.168.1.0/24"`)  
- `-s, --scan_type`: **Scan type** ("arp" or "ping", **default**: "arp")  
- `-p, --port_range`: **Port range to scan** (**default**: "1-1024")  
- `-o, --output`: **Output file** (**default**: "report.json")  
- `-f, --format`: **Output format** (**currently supported**: "json")  

📌 **Example**:  
```bash
network-scan -t 192.168.1.0/24 -s arp -p 1-100 -o network_scan.json
```

## ⚠️ Important Notes  

Some features require **root/administrator privileges**:  
🔹 **ARP scanning**  
🔹 **PING scanning**  
🔹 **Port scanning**  

💡 **Run with sudo/administrator privileges if needed**:  
```bash
sudo network-scan -t 192.168.1.0/24
```

## 📜 License  

📝 **MIT License** - Open-source project, free to use and modify.
