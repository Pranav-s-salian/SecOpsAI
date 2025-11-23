# 🛡️ Intelligent Wazuh SIEM Analyzer

> **The Future of Security Operations: AI-Driven, Context-Aware, and Available Anywhere.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![React](https://img.shields.io/badge/react-18.0%2B-61DAFB)
![Wazuh](https://img.shields.io/badge/Wazuh-Ready-blueviolet)
![AI](https://img.shields.io/badge/AI-Groq%20Llama%203-orange)

---

## 🚀 Overview

The **Intelligent Wazuh SIEM Analyzer** is a next-generation **Intelligent AI Agent-based System** designed to empower Security Operations Center (SOC) analysts. By bridging the gap between complex SIEM data and natural language, it allows analysts to interact with their security infrastructure as if they were talking to a senior colleague.

Instead of writing complex SQL or Elasticsearch DSL queries, simply ask:
> *"Show me all failed SSH login attempts from yesterday that look like a brute force attack."*

The system uses **Advanced AI (Groq Llama 3)** to understand your intent, query your **Wazuh/Elasticsearch** data, and provide actionable, intelligent security insights in seconds. It acts as an autonomous agent that can reason about security events, formulate investigation plans, and execute them across your infrastructure.

**✨ True Freedom for Analysts:** Manage your entire SOC from your smartphone via our advanced Telegram integration. Whether you are in the office, at home, or on the move, SecurAI ensures you never miss a critical threat.

---

## 💡 How It Helps Security Analysts

| Feature | Benefit |
|---------|---------|
| **🗣️ Natural Language Interface** | No need to learn complex query languages. Just ask questions in plain English. |
| **🧠 AI-Powered Context** | The AI doesn't just fetch data; it **analyzes** it. It detects patterns (like brute force), assesses risk, and suggests remediation. |
| **⚡ Real-Time Auto-Monitoring** | Switch to "Auto Mode" and let the AI scan your logs every 10 seconds for suspicious activity, alerting you instantly. |
| **🔍 Deep Forensics** | Correlates data across authentication logs, network traffic, and system alerts to give a complete picture of an incident. |
| **📉 Reduced Fatigue** | Automates the repetitive task of sifting through thousands of logs, allowing analysts to focus on high-value threat hunting. |
| **🌍 Total Mobility** | **Work from anywhere.** Monitor via dashboard on your laptop or chat with the AI via Telegram on your mobile. |

---

## ️ Tech Stack

We utilize a cutting-edge stack to deliver speed, reliability, and intelligence.

### **Backend & AI**
*   ![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue) **Python 3**: Core logic and orchestration.
*   ![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white) **Flask**: REST API and WebSocket server.
*   ![Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white) **Elasticsearch**: High-performance log storage and retrieval.
*   ![Groq](https://img.shields.io/badge/Groq-AI-orange?style=for-the-badge) **Groq (Llama 3.3)**: Ultra-fast AI inference for decision making.
*   ![LangChain](https://img.shields.io/badge/LangChain-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white) **LangChain**: AI workflow orchestration.

### **Frontend**
*   ![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB) **React**: Dynamic and responsive user interface.
*   ![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white) **TypeScript**: Type-safe code for reliability.
*   ![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white) **Tailwind CSS**: Modern styling.
*   ![Vite](https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white) **Vite**: Blazing fast build tool.

---

## 🔌 Connecting to Your Infrastructure

To unleash the full power of this analyzer on your company's infrastructure, follow this professional deployment workflow:

### **Step 1: Deploy Wazuh Agents**
First, you need visibility. Install the Wazuh Agent on the endpoints you want to monitor (Servers, Workstations, Cloud Instances).

*   **Linux**:
    ```bash
    curl -so wazuh-agent.sh https://packages.wazuh.com/4.7/wazuh-agent.sh && sudo bash ./wazuh-agent.sh
    ```
*   **Windows**:
    Download the MSI installer and run:
    ```powershell
    wazuh-agent-4.7.0-1.msi /q WAZUH_MANAGER="YOUR_WAZUH_SERVER_IP"
    ```

### **Step 2: Connect to Wazuh Manager**
Ensure the agents are reporting to your central Wazuh Manager.
1.  Start the agent: `systemctl start wazuh-agent` (Linux) or `net start WazuhSvc` (Windows).
2.  Verify connection in your Wazuh Dashboard.

### **Step 3: Connect the Intelligent Analyzer**
Configure the Analyzer to talk to your data sources.
1.  Update `intelligent_wazuh_analyzer.py` with your **Elasticsearch** URL (e.g., `http://your-elastic-server:9200`).
2.  Update `wazuh-mcp-server/config.py` with your **Wazuh Manager** API credentials.

### **Step 4: Activate AI Monitoring**
Run the system! The AI will now have access to real-time telemetry from all your connected agents. It will begin correlating events, detecting anomalies, and answering your questions about the entire fleet.

---

## 💬 Conversational Security: Chat Like a Human

One of the most powerful features of this analyzer is its ability to understand **casual, conversational language**. You don't need to be formal or technical. The AI is smart enough to figure out what you need, even if you ask vaguely.

### **Formal vs. Casual - It Handles Both:**

| **Formal Query** | **Casual Query (Also Works!)** |
|------------------|--------------------------------|
| *"Show me all failed SSH login attempts from the last 24 hours."* | *"Hey, did anyone try to break in yesterday?"* |
| *"List all agents with status 'disconnected'."* | *"Which computers are offline right now?"* |
| *"Analyze network traffic for port 22 anomalies."* | *"Is there anything weird happening with SSH?"* |
| *"Display high severity alerts."* | *"What's the scariest thing you found today?"* |
| *"Give me a summary of security events."* | *"What's up? Anything I should worry about?"* |

**Why this matters:**
*   **Speed:** In a crisis, you don't have time to craft perfect queries. Just ask.
*   **Accessibility:** Junior analysts can be effective immediately without mastering complex query languages.
*   **Context:** The AI infers context. If you say "What about the other server?", it understands you're comparing to the previous result.

---

## ⚡ Quick Start & Testing

Want to see it in action immediately? We've included tools to simulate a live environment.

### 1. Prerequisites
*   Python 3.8+
*   Node.js & npm
*   Elasticsearch running locally (port 9200)

### 2. Installation

**Clone the repository:**
```bash
git clone https://github.com/your-org/intelligent-wazuh-analyzer.git
cd intelligent-wazuh-analyzer
```

**Backend Setup:**
```bash
# Install Python dependencies
pip install -r backend_requirements.txt
```

**Frontend Setup:**
```bash
cd frontend
npm install
cd ..
```

### 3. Simulate Data (Optional)
If you don't have a live Wazuh setup yet, use our simulation tools:

**Clear existing data:**
```bash
python clear_database.py
```

**Populate with realistic security scenarios:**
```bash
python populate_test_data.py
```
*This generates realistic logs: Brute force attacks, successful logins, malware alerts, and network scans.*

### 4. Run the System

**Start the Backend (API & AI Engine):**
```bash
python routes.py
```
*Server starts on `http://localhost:5000`*

**Start the Frontend (Dashboard):**
```bash
cd frontend
npm run dev
```
*Dashboard opens at `http://localhost:5173`*

---

## 📱 Telegram Bot Integration - SecOpsAi Bot (NEW!)

**Get instant security alerts on your phone - no dashboard required!**

SecurAI now includes **@SecOpsAi_bot** - an intelligent Telegram bot that monitors your infrastructure 24/7 and sends real-time threat notifications directly to your phone.

### 🚀 Zero Configuration Setup:
1. **Start the backend**: `python routes.py` (Bot starts automatically!)
2. **Open Telegram** and search for: **@SecOpsAi_bot**
3. **Send `/start`** to activate alerts
4. **Done!** You'll now receive instant security alerts

### 🛡️ Two Powerful Modes:

#### 1. 🔍 Auto Mode (Silent Guardian)
The AI works in the background, scanning your infrastructure every 10 seconds. It respects your time and peace of mind—you only get notified when a **real threat** is detected.
- **Zero Noise:** No spam, only high-fidelity alerts.
- **Instant Reaction:** Notifications arrive within seconds of detection.
- **Continuous Protection:** 24/7 monitoring without human intervention.

#### 2. 💬 Conversation Mode (AI Analyst in Your Pocket)
Switch to Conversation Mode to chat directly with the AI Security Analyst.
- **Ask Anything:** "Check the status of web-server-01", "Any failed logins in the last hour?"
- **Deep Dive:** Investigate alerts immediately from your phone.
- **Natural Language:** Speak naturally, the AI understands context and security terminology.

*Switching modes is seamless: Send `/auto` or `/conversation` to the bot.*

### 💡 Why Use Telegram Bot?
- **No Dashboard Needed**: Receive alerts even when you're away from your computer
- **Mobile-First**: Perfect for on-call analysts and remote teams
- **Multi-User**: Entire SOC team can subscribe and receive the same alerts
- **Real-Time**: Notifications arrive within seconds of threat detection

### 📱 Sample Alert:
```
🚨 SECURITY ALERT - THREAT DETECTED! 🚨

⏰ Time: 2025-11-23 14:32:15
📊 Suspicious Events: 12
🔍 Checks Triggered: 2

🔴 Finding #1: Brute Force Indicators
   • Severity: HIGH
   • Events: 8
   • Description: Multiple authentication_failed attempts...
   • Agent: web-server-01

⚠️ ACTION REQUIRED: Investigate immediately!
```

See [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md) for detailed instructions and commands.

---

## 🖥️ Usage Guide

### **Normal Mode (Interactive)**
Use the chat interface to ask questions.
*   *"Who logged into the production server after hours?"*
*   *"Are there any high severity alerts from the last hour?"*
*   *"Check agent 'web-server-01' for vulnerabilities."*

### **Auto Mode (Continuous Monitoring)**
Toggle the **"Auto Mode"** switch in the dashboard.
*   The AI will scan your infrastructure every 10 seconds.
*   It applies heuristic models to detect threats in real-time.
*   **Alerts** will pop up instantly if suspicious activity is found.
*   **📱 Telegram Integration**: Receive alerts directly on your phone! Send `/start` to the bot for instant notifications.

---


## 🤝 Contributing

We welcome contributions from the security community! Please read `CONTRIBUTING.md` for details on our code of conduct and the process for submitting pull requests.

---

**Built with ❤️ for the Blue Team.**
