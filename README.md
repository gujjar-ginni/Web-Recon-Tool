# 🕵️‍♀️ Rapid Recon

**Rapid Recon** is a Python-based reconnaissance and information-gathering tool that automates various intelligence-gathering techniques for cybersecurity professionals, ethical hackers, and SOC analysts.  

It collects crucial data such as **DNS records, GeoIP info, WHOIS data, open ports, HTTP headers, technologies used**, and generates structured reports.

---

## 🔧 Features

- 🔎 **DNS Lookup** – Queries DNS records (subdomains, mail servers, name servers, etc.)  
- 🌍 **GeoIP Lookup** – Pinpoints the physical location of the target IP address  
- 🌐 **HTTP Info** – Fetches response headers, status codes, server information  
- 🕵️ **WHOIS Lookup** – Extracts registration information and domain lifecycle  
- 🚪 **Port Scanning** – Detects open TCP ports using socket connections  
- 💻 **Technology Detection** – Identifies backend/frontend tech stack  
- 📤 **Export to JSON** – Saves all results in structured JSON format  
- 📝 **Report Generator** – Compiles results into a human-readable summary  
- ✅ **Input Validation** – Ensures clean and valid user inputs (IP/domain)  

---

## 🚀 Getting Started

### 📌 Prerequisites
- Python **3.8+**  
- Internet connection (for external lookups)  
- Recommended: Virtual environment  
- `.env` file with your API key:  
  ```env
  IPINFO_TOKEN=your_token
⚙️ Installation & Usage
Clone the repository and install dependencies:

bash
Copy
Edit
git clone https://github.com/gujjar-ginni/Rapid-Recon.git
cd Rapid-Recon
pip install -r requirements.txt
Run the tool:

bash
Copy
Edit
python recon.py --help
python recon.py --all example.com
📂 Project Structure
bash
Copy
Edit
Rapid-Recon/
│── recon.py          # Main script
│── modules/          # Recon logic (DNS, WHOIS, ports, etc.)
│── reports/          # Generated reports
│── requirements.txt  # Python dependencies
│── .env.example      # Example environment variables
│── README.md         # Documentation
📜 Reports
Reports are automatically saved inside the reports/ folder

Supported formats: JSON, Text Summary

🤝 Contributing
Pull requests are welcome!
For major changes, please open an issue first to discuss what you would like to change.

⚖️ License
This project is licensed under the MIT License – see the LICENSE file for details.

yaml
Copy
Edit

---

👉 Ye ekdum **GitHub-ready** hai — sahi headings, emojis, aur structure ke sath.  

Kya aap chahte ho mai aapke liye ek **`.gitignore`** bhi bana du taaki `reports/`, `.venv/`, aur `__pycache__/` jaise folders GitHub pe upload na ho?
