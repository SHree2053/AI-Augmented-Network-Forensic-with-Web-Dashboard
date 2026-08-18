# NetForensic – AI-Augumented Network Forensics Tool

## Features
- Upload PCAP files and detect attacks using XGBoost.
- Real‑time packet capture.
- Dashboard with charts, alerts, and threat intelligence.
- LLM integration for natural language querying.

## Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Run migrations: `python manage.py migrate`
3. Start the server: `python manage.py runserver`

## Usage
- Upload a PCAP file to analyse.
- View live traffic and alerts on the dashboard.
- Use the LLM Query page to ask questions about the network data.

## Technologies
- Django, XGBoost, Isolation Forest, scapy, VirusTotal API, Ollama.
