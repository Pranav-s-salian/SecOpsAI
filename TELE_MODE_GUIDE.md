# 📱 Tele Mode - Chat with AI from Telegram

## Overview
**Tele Mode** allows security analysts to interact with SecurAI directly through Telegram, making it perfect for mobile investigations and on-the-go security queries.

---

## 🎯 Two Operating Modes

### 1️⃣ **Auto Mode** (Threat Monitoring)
- **Purpose**: Continuous automated threat detection
- **How it works**: AI scans every 10 seconds for threats
- **Notifications**: Alerts sent to Telegram automatically
- **Interaction**: None required - fully automated

### 2️⃣ **Tele Mode** (Interactive Chat)
- **Purpose**: Ask security questions from your phone
- **How it works**: Type questions in Telegram, AI responds
- **Notifications**: Get AI responses directly in Telegram
- **Interaction**: Full conversational AI access

---

## 🚀 How to Use Tele Mode

### Step 1: Enable Tele Mode
1. Open the SecurAI dashboard
2. Find the **"Tele Mode"** toggle
3. Switch it **ON**
4. You'll see: **"Tele Mode ON - Communicate through Telegram"**

### Step 2: Chat in Telegram
1. Open Telegram app on your phone
2. Go to **@SecOpsAi_bot**
3. Type your security questions naturally:
   ```
   Show me failed login attempts from yesterday
   
   Any suspicious activity on web-server-01?
   
   What's the latest threat?
   
   Check authentication logs for IP 192.168.1.50
   ```

### Step 3: Get AI Responses
- AI processes your query using the same intelligence as the dashboard
- Response appears **directly in Telegram** within seconds
- Same response also shows in the dashboard for logging

---

## 💡 Use Cases

| Scenario | Mode |
|----------|------|
| **Continuous monitoring while working** | Auto Mode ON |
| **Investigating from mobile/away from desk** | Tele Mode ON |
| **Both monitoring AND mobile chat** | Both ON |
| **Desktop-only investigation** | Both OFF (use dashboard) |

---

## 🔄 Mode Combinations

### ✅ Auto Mode ON + Tele Mode OFF
- **Behavior**: Automated threat scanning
- **Telegram**: Receives alerts only
- **Dashboard**: Can still chat normally

### ✅ Auto Mode OFF + Tele Mode ON
- **Behavior**: No automated scanning
- **Telegram**: Full chat functionality
- **Dashboard**: Shows "Tele Mode ON" - keyboard disabled
- **Perfect for**: Mobile-only investigations

### ✅ Both ON
- **Behavior**: Automated scanning + Chat available
- **Telegram**: Receives alerts AND can chat
- **Dashboard**: Can see both alerts and Telegram conversations

### ✅ Both OFF
- **Behavior**: Normal dashboard operation
- **Telegram**: No interaction
- **Dashboard**: Standard chat mode

---

## 🎨 Dashboard Behavior

### When Tele Mode is ON:
```
┌─────────────────────────────────────┐
│  🖥️ SecurAI Dashboard               │
├─────────────────────────────────────┤
│                                     │
│  📱 TELE MODE ON                    │
│                                     │
│  Communicate through Telegram       │
│                                     │
│  💬 Messages from Telegram:         │
│  ┌───────────────────────────────┐ │
│  │ @john: Show me alerts         │ │
│  │ 🤖 AI: Found 3 high-severity  │ │
│  │        alerts...               │ │
│  └───────────────────────────────┘ │
│                                     │
│  [ Chat input is disabled ]         │
│                                     │
└─────────────────────────────────────┘
```

---

## 📲 Telegram Commands

| Command | Description |
|---------|-------------|
| `/start` | Activate bot and see current mode status |
| `/stop` | Unsubscribe from alerts |
| `/status` | Check bot status and modes |
| *Any text* | Treated as AI query when Tele Mode is ON |

---

## 🔒 Security Features

✅ **Authentication**: Only users who sent `/start` can interact  
✅ **Logging**: All Telegram queries are logged in dashboard  
✅ **Multi-user**: Multiple team members can chat simultaneously  
✅ **Sync**: Dashboard shows all Telegram conversations in real-time  

---

## 🎯 Example Workflow

**Scenario**: You're away from your desk and get an alert on your phone

1. **Alert arrives** via Auto Mode:
   ```
   🚨 SECURITY ALERT
   Brute force detected on web-server-01
   ```

2. **You want more details**, so you enable Tele Mode in dashboard (or ask colleague to)

3. **You ask in Telegram**:
   ```
   Show me all failed login attempts on web-server-01 in the last hour
   ```

4. **AI responds in Telegram**:
   ```
   🤖 SecurAI Response:
   
   Found 25 failed SSH attempts:
   - Source IP: 192.168.1.99
   - Target user: root
   - Time pattern: Every 30 seconds
   - Risk: HIGH - Active brute force attack
   
   RECOMMENDATION: Block IP immediately
   ```

5. **You take action** based on mobile investigation - no desktop needed!

---

## ⚙️ Technical Details

### WebSocket Events
- `start_tele_mode` - Enable Tele Mode
- `stop_tele_mode` - Disable Tele Mode
- `telegram_message` - Message received from Telegram user
- `telegram_response` - AI response sent to Telegram

### REST Endpoints
- `POST /tele_mode` - Toggle Tele Mode

### Backend Flow
```
Telegram User → @SecOpsAi_bot → tele_bot.py → routes.py 
→ IntelligentWazuhAnalyzer → Groq AI → Response 
→ routes.py → tele_bot.py → Telegram User
            ↓
        Dashboard (Frontend)
```

---

## 🚨 Important Notes

1. **Tele Mode requires bot to be running** (starts automatically with `python routes.py`)
2. **Users must send `/start`** to the bot before chatting
3. **Long responses are split** (Telegram has 4096 character limit)
4. **Dashboard input is disabled** when Tele Mode is ON (prevents confusion)
5. **All AI settings are unchanged** - same intelligence, just mobile access

---

## 🐛 Troubleshooting

### Tele Mode not working?
- ✅ Check bot is running (`python routes.py`)
- ✅ Verify you sent `/start` to @SecOpsAi_bot
- ✅ Confirm Tele Mode toggle is ON in dashboard
- ✅ Try `/status` in Telegram to check bot status

### Not receiving responses?
- ✅ Check backend logs for errors
- ✅ Ensure Telegram bot token is valid
- ✅ Verify internet connection
- ✅ Try simpler query first

---

**🎉 Now you can investigate security incidents from anywhere, anytime!**
