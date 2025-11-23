# 📱 Telegram Bot Workflow

## Complete User Journey

### 1️⃣ Initial Setup
1. Start the backend: `python routes.py`
2. Telegram bot auto-starts and begins listening
3. Open Telegram and search for `@SecOpsAi_bot`

### 2️⃣ Bot Activation
**User sends:** `/start`

**Bot responds:**
```
🤖 Welcome to SecurAI Security Bot!

Please select your mode:

🔍 /auto - Auto Mode
   • Activates automated threat scanning
   • Receive real-time security alerts
   • Monitors for brute force, malware, suspicious activity
   • Alerts sent automatically when threats detected

💬 /conversation - Conversation Mode
   • Chat directly with AI security analyst
   • Ask questions about your infrastructure
   • Get instant security insights
   • Interactive investigation mode

Choose a mode to get started! 🚀
```

### 3️⃣ Mode Selection

#### Option A: Auto Mode
**User sends:** `/auto`

**Bot responds:**
```
🔍 Auto Mode ACTIVATED!

✅ Automated threat scanning is now running
✅ You will receive real-time alerts for:
   • High-severity security events
   • Brute force attempts
   • Suspicious authentication activity
   • Malware detections
   • Critical system alerts

The system will scan every 10 seconds and notify you immediately when threats are detected.

Send /conversation to switch to chat mode
Send /status to check current status
```

**What happens:**
- Frontend dashboard automatically enables Auto Mode
- Elasticsearch scanning starts every 10 seconds
- Security alerts sent to Telegram whenever threats detected
- Dashboard shows scan status in real-time

---

#### Option B: Conversation Mode
**User sends:** `/conversation`

**Bot responds:**
```
💬 Conversation Mode ACTIVATED!

You can now chat with the AI security analyst directly!

Just type your questions naturally:
• "Show me failed login attempts today"
• "Any suspicious activity in the last hour?"
• "Check status of all agents"
• "Find brute force attacks this week"
• "What security alerts do we have?"

The AI will analyze your infrastructure and respond right here in Telegram! 🤖

Send /auto to switch to automated scanning
Send /status to check current status
```

**What happens:**
- Frontend dashboard automatically enables Conversation Mode
- Any message you send gets processed by AI
- Response comes back to Telegram within seconds
- Dashboard shows your Telegram messages and AI responses

### 4️⃣ Using Conversation Mode

**User sends:** `show me failed login attempts today`

**Bot responds:**
```
🤔 Processing your query...

[AI analyzes Elasticsearch data]

🤖 SecurAI Response:

================================================================================
FINDINGS SUMMARY - WHAT WAS DISCOVERED
================================================================================

**Original Query:** `show me failed login attempts today`
**Detected Intent:** `AUTHENTICATION`
**Time Range:** `TODAY`

✅ TOTAL ITEMS FOUND: 47

**DETAILED FINDINGS:**

### Finding 1: Authentication Events
- Source: Elasticsearch
- Count: 47 items

Sample Events:

1. [2025-01-15 14:23:45] (Level 5)
   - Description: Failed password for invalid user admin
   - Agent: web-server-01
   - Source IP: 192.168.1.105

...

[Full AI analysis with security recommendations]
```

### 5️⃣ Switching Modes

**Switch from Auto Mode to Conversation Mode:**
- Send `/conversation` in Telegram
- Auto scanning stops
- Conversation mode activates

**Switch from Conversation Mode to Auto Mode:**
- Send `/auto` in Telegram  
- Conversation mode stops
- Auto scanning starts

### 6️⃣ Other Commands

**Check Status:**
```
User: /status

Bot: 📊 SecurAI Bot Status

🤖 Bot: Active
👥 Active Users: 1

Current Modes:
🔍 Auto Mode: ✅ ENABLED
💬 Conversation Mode: ❌ DISABLED

Use /auto or /conversation to switch modes.
```

**Stop Bot:**
```
User: /stop

Bot: ❌ Bot stopped. Send /start to re-enable.
```

## 🔧 Technical Flow

### Backend Processing (routes.py)

1. **Global Callback Registered:**
   - `telegram_chat_callback()` handles ALL Telegram messages
   - Registered during bot initialization
   - Routes commands to appropriate handlers

2. **Command Processing:**
   ```python
   /auto → auto_mode_active[client_id] = True
         → Emits 'auto_mode_started' to frontend
         → Starts background scanning task
   
   /conversation → tele_mode_active[client_id] = True
                 → Emits 'tele_mode_started' to frontend
                 → Enables chat message processing
   ```

3. **Message Processing:**
   ```python
   Regular message → Check if tele_mode_active
                   → Process with IntelligentWazuhAnalyzer
                   → Send response to Telegram
                   → Emit to frontend dashboard
   ```

### Frontend Processing (Chat.tsx)

1. **WebSocket Listeners:**
   ```typescript
   'auto_mode_started' → Set autoMode=true
   'tele_mode_started' → Set teleMode=true
   'telegram_message'  → Display in chat with 📱 prefix
   'telegram_response' → Display AI response
   ```

2. **Mode Buttons:**
   - Auto Mode button triggers `emit('start_auto_mode')`
   - Conversation Mode button triggers `emit('start_tele_mode')`
   - Buttons are mutually exclusive

## 🎯 Use Cases

### Security Analyst On-Call
1. Receive `/start` notification during off-hours
2. Send `/auto` to monitor threats from mobile
3. Get instant alerts when attacks detected
4. Switch to `/conversation` for investigation
5. Ask specific questions about suspicious IPs

### Security Operations Center (SOC)
1. Dashboard operators monitor frontend
2. Field analysts use Telegram for remote access
3. Analysts send `/conversation` from mobile
4. Query infrastructure without desktop access
5. Receive AI insights on the go

### Incident Response
1. Alert triggered in Auto Mode
2. Analyst receives Telegram notification
3. Switches to `/conversation` mode
4. Investigates: "Show me all events from IP 192.168.1.105"
5. AI provides detailed forensic analysis
6. Takes action based on AI recommendations

## 🚨 Security Alert Example (Auto Mode)

When threat detected, Telegram receives:
```
🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨
SECURITY ALERT - THREAT DETECTED!
🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨

⏰ Time: 2025-01-15 14:30:15
🔴 Suspicious Events: 12
🔬 Checks Triggered: 2

FINDINGS:

🔴 Finding #1: Brute Force Indicators
   • Severity: HIGH
   • Events: 8
   • Description: Multiple authentication failures from same IP
   • Agent: web-server-01

🟠 Finding #2: Failed Authentication Attempts
   • Severity: MEDIUM
   • Events: 4
   • Description: Invalid user login attempts
   • Agent: database-server-02

⚡ ACTION REQUIRED: Investigate these threats immediately!
🖥️ Check your SecurAI dashboard for full details.
```

## 📊 Commands Summary

| Command | Description | Effect |
|---------|-------------|--------|
| `/start` | Activate bot | Shows mode selection menu |
| `/auto` | Auto Mode | Enables threat scanning & alerts |
| `/conversation` | Chat Mode | Enables AI chat via Telegram |
| `/status` | Show status | Displays current mode & bot info |
| `/stop` | Deactivate | Stops receiving messages |

## 🛠️ Troubleshooting

**Bot not responding to /start:**
- Check backend is running (`python routes.py`)
- Verify bot token is correct
- Check terminal for "[TELEGRAM] Bot Connected" message

**Commands not triggering frontend:**
- Ensure frontend is connected to backend
- Check browser console for WebSocket connection
- Verify dashboard shows "Connected" status

**No AI responses in Conversation Mode:**
- Confirm `/conversation` was sent first
- Check backend logs for processing messages
- Verify Groq API key is configured

**Auto Mode not scanning:**
- Confirm `/auto` command was sent
- Check dashboard shows "Auto Mode" enabled
- Verify Elasticsearch is running and accessible

## 🎉 Success Criteria

✅ Send `/start` → Receive welcome menu
✅ Send `/auto` → Dashboard Auto Mode activates
✅ Send `/conversation` → Dashboard Conversation Mode activates
✅ Send question → Receive AI response in Telegram
✅ Threat detected → Receive alert in Telegram
✅ Frontend shows Telegram messages with 📱 prefix
