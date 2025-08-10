# HOTSPOT DATA MANAGER

A Streamlit-based dashboard for monitoring and controlling per-device internet usage on your network.  
You can **set data limits for each device**, view **live usage**, and **automatically block devices** when they exceed their quota.

---

## 🚀 Features

- 📊 **Live Data Usage** — See real‑time network usage for each connected device.
- 🎯 **Per‑Device Data Limits** — Set a specific data quota (MB) for each device.
- ⛔ **Automatic Blocking** — Device is blocked automatically when its quota is exceeded.
- 🔄 **Automatic Unblocking** — Devices can be unblocked manually or once under quota.
- 🖥 **Simulation Mode** — Works even in environments without admin rights, such as Streamlit Cloud.
- 💻 **Cross‑Platform** — Live capture on Windows with admin rights, simulation elsewhere.
- 🌐 **User Login** — Protects controls with username/password authentication.
- 🧹 **Clean, Modern UI** — Styled dashboard with side panel info.

-------------------------------------------------------------------------------------------------------------------

## 📥 How to Run


### 2️⃣ Cloud Deployment (Simulation Mode)

1. Push this repository to GitHub (already done).
2. Go to [Streamlit Cloud](https://streamlit.io/cloud) and log in.
3. Click **"New app"** > Select this repository > Branch: `main` > File: `app.py`
4. Deploy and get your public link!

---

## 💡 About the Project

In a shared network, one device can consume most of the bandwidth, slowing the internet for others.  
**Hotspot Data Manager** solves this by letting the network admin:
- Set per‑device data limits to keep usage fair
- Monitor usage in real time
- Automatically block devices that exceed their quota

Even in the 5G era, **data fairness** is important for shared networks like:
- Home Wi‑Fi with limited monthly data
- Public hotspots in cafes/hostels
- Small office or school networks

---

## 🔑 Login Details (Default)

- **Username:** `admin`
- **Password:** `admin123`



## 👤 Author

**Mohammad Ilhan**  
[GitHub Profile](https://github.com/Mohammad-ilhan)

---


### 1️⃣ Local Installation (Full Features)

**Requirements:**
- Python 3.8+
- Windows (Admin rights for live capture & blocking)
- Or any OS (Simulation mode only)



