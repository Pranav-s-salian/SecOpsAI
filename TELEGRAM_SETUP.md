# 📱 Telegram Bot Integration - Setup Guide

## Overview
The SecurAI Telegram bot sends real-time security alerts directly to your Telegram when threats are detected during Auto Mode scanning.

---

## Quick Setup

### 1. Start the Backend
```bash
python routes.py
```

### 2. Open Telegram
- Open Telegram on your phone or desktop
- Search for: **@SecOpsAIBot** (or use the bot token directly)

### 3. Activate the Bot
Send this command to the bot:
```
/start
```

You should receive a welcome message:
```
🤖 SecurAI Security Bot Activated!

✅ Bot is now running and monitoring your infrastructure.

You will receive real-time alerts when threats are detected...
```

### 4. Enable Auto Mode
In the SecurAI frontend dashboard:
- Toggle the **"Auto Mode"** switch
- You'll see a notification about Telegram being available
- The system will start scanning every 10 seconds

### 5. Receive Alerts
When a threat is detected:
- ✅ Alert appears in the frontend dashboard
- ✅ **Same alert is sent to your Telegram instantly!**

---

## Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Activate alerts and subscribe to notifications |
| `/stop` | Deactivate alerts and unsubscribe |
| `/status` | Check bot status and active users |

---

## How It Works

```
┌─────────────────┐
│   Auto Mode     │
│   Activated     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Scan Every     │
│  10 Seconds     │
└────────┬────────┘
         │
         ▼
    ┌────────┐
    │ Threat │ ◄── NO  ──► Continue Scanning
    │ Found? │
    └────┬───┘
         │
        YES
         │
         ▼
┌─────────────────────────────┐
│  Send Alert To:             │
│  • Frontend Dashboard  ✅   │
│  • Telegram Subscribers ✅  │
└─────────────────────────────┘
```

---

## Alert Example

When a brute force attack is detected, you'll receive this on Telegram:

```
🚨 SECURITY ALERT - THREAT DETECTED! 🚨

⏰ Time: 2025-11-23 14:32:15
📊 Suspicious Events: 12
🔍 Checks Triggered: 2

📋 FINDINGS:

🔴 Finding #1: Brute Force Indicators
   • Severity: HIGH
   • Events: 8
   • Description: Multiple authentication_failed attempts detected...
   • Agent: web-server-01

🟠 Finding #2: Failed Authentication Attempts
   • Severity: MEDIUM
   • Events: 4
   • Description: authentication_failed from unknown source...
   • Agent: db-server-02

⚠️ ACTION REQUIRED: Investigate these threats immediately!
🔗 Check your SecurAI dashboard for full details.
```

---

## Features

✅ **Real-time notifications** - Get alerts within seconds of detection  
✅ **Multi-user support** - Multiple team members can subscribe  
✅ **Detailed findings** - See severity, event counts, and descriptions  
✅ **Actionable intel** - Know exactly what to investigate  
✅ **Always on** - Bot runs as long as the backend is active  

---

## Configuration

The bot token is configured in `tele_bot.py`:
```python
self.bot_token = 
```

### Security Note
In production, store the token in environment variables:
```bash
export TELEGRAM_BOT_TOKEN="your_token_here"
```

Then update `tele_bot.py`:
```python
import os
self.bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
```

---

## Troubleshooting

### Bot Not Responding
1. Check backend logs for Telegram connection status
2. Verify the bot token is correct
3. Ensure you've sent `/start` to the bot

### Not Receiving Alerts
1. Confirm Auto Mode is enabled in the frontend
2. Check that you've subscribed with `/start`
3. Verify backend shows "Telegram bot started successfully"

### Multiple Users
- Each user must send `/start` to their own Telegram
- All subscribed users receive the same alerts
- Check subscriber count with `/status`

---

## Testing

Test the bot without waiting for real threats:

```bash
# Run the bot test script
python tele_bot.py
```

This will:
- Start the Telegram bot
- Wait for your `/start` command
- Keep running until you press Ctrl+C

---

## API Endpoints

Check bot status programmatically:

```bash
curl http://localhost:5000/telegram/status
```

Response:
```json
{
  "status": "success",
  "telegram": {
    "running": true,
    "active_users": 2,
    "has_subscribers": true
  }
}
```

---

**🎯 Now you're ready to receive instant security alerts on Telegram!**
