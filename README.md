# netcut

Network control tool for your local network. Scan devices, monitor bandwidth, block or throttle connections.

Built with Python (FastAPI, Scapy) and Next.js.

## Setup

**Backend:**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Frontend:**
```bash
cd frontend
npm install
```

## Running

```bash
# Backend (needs root for raw sockets)
cd backend
sudo $(which python) api.py

# Frontend
cd frontend
npm run dev
```

Go to http://localhost:3000

## How it works

Uses ARP spoofing to intercept traffic between devices and the router. Once in the middle, you can monitor bandwidth or use iptables/tc to block or limit connections.

Only works on local networks. Requires Linux.

## API

Docs available at http://localhost:8000/docs when backend is running.
