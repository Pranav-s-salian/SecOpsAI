"""
Telegram Bot for SecurAI - Real-time Security Alerts
Sends threat notifications to Telegram when Auto Mode detects suspicious activity
"""

import asyncio
import httpx
from typing import Optional, List
import json
from datetime import datetime


class TelegramSecurityBot:
    """Telegram bot that forwards security alerts from Auto Mode"""
    
    def __init__(self):
        self.bot_token = "you must put your telegram bot token here"
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.chat_ids: List[int] = []  # Store active chat IDs
        self.is_running = False
        self.client: Optional[httpx.AsyncClient] = None
        self.last_update_id = 0
        self.tele_mode_active = False  # NEW: Track if Tele Mode is enabled
        self.tele_mode_callback = None  # Callback to send messages to frontend
    
    async def start(self):
        """Start the Telegram bot"""
        print("\n" + "=" * 70)
        print(" TELEGRAM SECURITY BOT STARTING...")
        print("=" * 70)
        
        self.is_running = True
        self.client = httpx.AsyncClient(timeout=30.0)
        
        # Test connection
        try:
            me = await self._api_call("getMe")
            if me and "result" in me:
                bot_name = me["result"].get("username", "SecurAI Bot")
                print(f" Bot Connected: @{bot_name}")
                print(f"Users can start the bot by sending /start to @{bot_name}")
                print(f"Threat alerts will be sent to all active users")
                print("=" * 70 + "\n")
            else:
                print("Failed to connect to Telegram API")
                return False
        except Exception as e:
            print(f"Bot connection failed: {e}")
            return False
        
        return True
    
    async def stop(self):
        """Stop the Telegram bot"""
        print("\nStopping Telegram bot...")
        self.is_running = False
        if self.client:
            await self.client.aclose()
        print("Telegram bot stopped")
    
    async def _api_call(self, method: str, **params):
        """Make API call to Telegram"""
        if not self.client:
            return None
        
        try:
            url = f"{self.base_url}/{method}"
            response = await self.client.post(url, json=params)
            return response.json()
        except Exception as e:
            print(f"[TELEGRAM] API call failed: {e}")
            return None
    
    def _poll_updates_sync(self):
        """Poll for new messages and commands (runs in separate thread)"""
        print("[TELEGRAM] Started listening for /start commands...")
        
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        while self.is_running:
            try:
                updates = loop.run_until_complete(
                    self._api_call("getUpdates", 
                                  offset=self.last_update_id + 1,
                                  timeout=30)
                )
                
                if updates and "result" in updates:
                    for update in updates["result"]:
                        self.last_update_id = update["update_id"]
                        loop.run_until_complete(self._handle_update(update))
                
                import time
                time.sleep(1)
            except Exception as e:
                print(f"[TELEGRAM] Polling error: {e}")
                import time
                time.sleep(5)
        
        loop.close()
    
    async def _handle_update(self, update: dict):
        """Handle incoming Telegram messages"""
        if "message" not in update:
            return
        
        message = update["message"]
        chat_id = message["chat"]["id"]
        text = message.get("text", "")
        user = message.get("from", {})
        username = user.get("username", user.get("first_name", "User"))
        
        print(f"[TELEGRAM] Message from @{username} (ID: {chat_id}): {text}")
        
        if text.startswith("/start"):
            # User activated the bot - show mode selection menu
            if chat_id not in self.chat_ids:
                self.chat_ids.append(chat_id)
                print(f"[TELEGRAM] New user registered: @{username} (ID: {chat_id})")
            
            welcome_message = """
**Welcome to SecurAI Security Bot!**

Please select your mode:

**/auto** - Auto Mode
   • Activates automated threat scanning
   • Receive real-time security alerts
   • Monitors for brute force, malware, suspicious activity
   • Alerts sent automatically when threats detected

**/conversation** - Conversation Mode
   • Chat directly with AI security analyst
   • Ask questions about your infrastructure
   • Get instant security insights
   • Interactive investigation mode

Choose a mode to get started!
"""
            await self.send_message(chat_id, welcome_message)
        
        elif text.startswith("/auto"):
            # Activate Auto Mode in frontend
            print(f"[TELEGRAM] User @{username} activated Auto Mode")
            
            # Notify backend to enable auto mode
            if self.tele_mode_callback:
                await self.tele_mode_callback("/auto", chat_id, username, is_command=True)
            
            response_msg = """
**Auto Mode ACTIVATED!**

Automated threat scanning is now running
You will receive real-time alerts for:
   • High-severity security events
   • Brute force attempts
   • Suspicious authentication activity
   • Malware detections
   • Critical system alerts

The system will scan every 10 seconds and notify you immediately when threats are detected.

Send /conversation to switch to chat mode
Send /status to check current status
"""
            await self.send_message(chat_id, response_msg)
        
        elif text.startswith("/conversation"):
            # Activate Conversation Mode
            print(f"[TELEGRAM] User @{username} activated Conversation Mode")
            
            # Notify backend to enable tele mode
            if self.tele_mode_callback:
                await self.tele_mode_callback("/conversation", chat_id, username, is_command=True)
            
            response_msg = """
**Conversation Mode ACTIVATED!**

You can now chat with the AI security analyst directly!

Just type your questions naturally:
• "Show me failed login attempts today"
• "Any suspicious activity in the last hour?"
• "Check status of all agents"
• "Find brute force attacks this week"
• "What security alerts do we have?"

The AI will analyze your infrastructure and respond right here in Telegram!

Send /auto to switch to automated scanning
Send /status to check current status
"""
            await self.send_message(chat_id, response_msg)
        
        elif text.startswith("/stop"):
            # User deactivated alerts
            if chat_id in self.chat_ids:
                self.chat_ids.remove(chat_id)
                print(f"[TELEGRAM] User unsubscribed: @{username} (ID: {chat_id})")
            
            await self.send_message(chat_id, "Bot stopped. Send /start to re-enable.")
        
        elif text.startswith("/status"):
            # Show bot status
            auto_mode_status = "ENABLED" if not self.tele_mode_active else "DISABLED"
            conversation_mode_status = "ENABLED" if self.tele_mode_active else "DISABLED"
            
            status_msg = f"""
**SecurAI Bot Status**

Bot: Active
Active Users: {len(self.chat_ids)}

**Current Modes:**
Auto Mode: {auto_mode_status}
Conversation Mode: {conversation_mode_status}

Use /auto or /conversation to switch modes.
"""
            await self.send_message(chat_id, status_msg)
        
        else:
            # Regular message - handle as chat if Conversation Mode is enabled
            if self.tele_mode_active and text and not text.startswith("/"):
                print(f"[TELEGRAM CHAT] Message from @{username}: {text}")
                
                # Notify that query is being processed
                await self.send_message(chat_id, "Processing your query...")
                
                # Send to frontend/backend for processing
                if self.tele_mode_callback:
                    try:
                        response = await self.tele_mode_callback(text, chat_id, username, is_command=False)
                        # Response will be sent back via send_chat_response()
                    except Exception as e:
                        print(f"[TELEGRAM CHAT ERROR] {e}")
                        await self.send_message(chat_id, f"Error processing query: {str(e)}")
                else:
                    await self.send_message(chat_id, "Conversation mode is not properly configured on the backend.")
            elif not self.tele_mode_active and text and not text.startswith("/"):
                # User sent message but not in conversation mode
                await self.send_message(chat_id, "Please activate Conversation Mode first by sending /conversation")
    
    async def send_message(self, chat_id: int, text: str, parse_mode: str = "Markdown"):
        """Send a message to a specific chat"""
        result = await self._api_call("sendMessage", 
                                      chat_id=chat_id,
                                      text=text,
                                      parse_mode=parse_mode)
        return result
    
    async def broadcast_alert(self, alert_message: str):
        """Send alert to all active users"""
        if not self.chat_ids:
            print("[TELEGRAM] No active users to send alerts to")
            return
        
        print(f"\n[TELEGRAM] Broadcasting alert to {len(self.chat_ids)} user(s)...")
        
        for chat_id in self.chat_ids:
            try:
                await self.send_message(chat_id, alert_message)
                print(f" [TELEGRAM] Alert sent to chat ID: {chat_id}")
            except Exception as e:
                print(f" [TELEGRAM] Failed to send to chat ID {chat_id}: {e}")
    
    async def send_threat_alert(self, findings: dict):
        """Format and send a threat detection alert"""
        
        # Format the alert message
        alert = "**SECURITY ALERT - THREAT DETECTED!**\n\n"
        alert += f" **Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        alert += f" **Suspicious Events:** {findings.get('total_suspicious', 0)}\n"
        alert += f" **Checks Triggered:** {len(findings.get('findings', []))}\n\n"
        
        alert += "**FINDINGS:**\n"
        
        for idx, finding in enumerate(findings.get('findings', [])[:3], 1):  # Limit to top 3
            severity_emoji = "" # Removed emoji
            
            alert += f"\n{severity_emoji} **Finding #{idx}: {finding['name']}**\n"
            alert += f"   • Severity: {finding['severity']}\n"
            alert += f"   • Events: {finding['count']}\n"
            
            # Add sample event details
            if finding.get('events'):
                event = finding['events'][0]
                source = event.get("_source", {})
                desc = source.get("rule", {}).get("description", "N/A")
                agent = source.get("agent", {}).get("name", "N/A")
                
                alert += f"   • Description: {desc[:80]}...\n"
                alert += f"   • Agent: {agent}\n"
        
        alert += f"\n **ACTION REQUIRED:** Investigate these threats immediately!\n"
        alert += f" Check your SecurAI dashboard for full details."
        
        # Broadcast to all users
        await self.broadcast_alert(alert)
    
    def get_active_users_count(self) -> int:
        """Get number of active users"""
        return len(self.chat_ids)
    
    def is_active(self) -> bool:
        """Check if bot is running and has active users"""
        return self.is_running and len(self.chat_ids) > 0
    
    def enable_tele_mode(self, callback_function):
        """Enable Tele Mode - users can chat with AI through Telegram"""
        self.tele_mode_active = True
        self.tele_mode_callback = callback_function
        print("[TELEGRAM] Tele Mode ENABLED - Chat functionality activated")
    
    def disable_tele_mode(self):
        """Disable Tele Mode"""
        self.tele_mode_active = False
        # Do not remove callback so we can re-enable it later via /conversation command
        # self.tele_mode_callback = None 
        print("[TELEGRAM] Tele Mode DISABLED")
    
    async def send_chat_response(self, chat_id: int, response: str):
        """Send AI response back to Telegram user"""
        # Split long responses if needed (Telegram has 4096 char limit)
        max_length = 4000
        if len(response) <= max_length:
            await self.send_message(chat_id, response)
        else:
            # Split into chunks
            chunks = [response[i:i+max_length] for i in range(0, len(response), max_length)]
            for idx, chunk in enumerate(chunks, 1):
                header = f"**Response Part {idx}/{len(chunks)}**\n\n" if len(chunks) > 1 else ""
                await self.send_message(chat_id, header + chunk)
    
    async def notify_tele_mode_change(self, enabled: bool):
        """Notify all users about Tele Mode status change"""
        if not self.chat_ids:
            return
        
        if enabled:
            message = """
**Tele Mode ACTIVATED!**

You can now chat with the AI directly through Telegram!

Just type your security questions naturally:
- "Show me failed login attempts"
- "Any suspicious activity today?"
- "Check agent status"

The AI will respond right here in Telegram!
"""
        else:
            message = """
**Tele Mode DEACTIVATED**

Chat mode is now disabled. You will only receive security alerts.

Send /start to see current status.
"""
        
        await self.broadcast_alert(message)


# Global bot instance
telegram_bot = TelegramSecurityBot()


async def start_telegram_bot():
    """Initialize and start the Telegram bot"""
    result = await telegram_bot.start()
    if result:
        # Start polling in background thread
        import threading
        polling_thread = threading.Thread(target=telegram_bot._poll_updates_sync, daemon=True)
        polling_thread.start()
        print("[TELEGRAM] Background polling thread started")
    return result


async def stop_telegram_bot():
    """Stop the Telegram bot"""
    await telegram_bot.stop()


async def send_security_alert(findings: dict):
    """Send security alert via Telegram"""
    if telegram_bot.is_active():
        await telegram_bot.send_threat_alert(findings)


def get_bot_status() -> dict:
    """Get current bot status"""
    return {
        "running": telegram_bot.is_running,
        "active_users": telegram_bot.get_active_users_count(),
        "has_subscribers": telegram_bot.is_active(),
        "tele_mode": telegram_bot.tele_mode_active
    }


async def enable_tele_chat_mode(callback_function):
    """Enable Telegram chat mode"""
    telegram_bot.enable_tele_mode(callback_function)
    await telegram_bot.notify_tele_mode_change(True)


async def disable_tele_chat_mode():
    """Disable Telegram chat mode"""
    telegram_bot.disable_tele_mode()
    await telegram_bot.notify_tele_mode_change(False)


async def send_telegram_chat_response(chat_id: int, response: str):
    """Send AI response back to Telegram"""
    await telegram_bot.send_chat_response(chat_id, response)


# For testing
async def test_bot():
    """Test the Telegram bot"""
    print("Testing Telegram Bot...")
    
    await start_telegram_bot()
    
    print("\n Send /start to your bot in Telegram to activate alerts")
    print("Waiting for commands... (Press Ctrl+C to stop)")
    
    try:
        # Keep running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping bot...")
        await stop_telegram_bot()


if __name__ == "__main__":
    # Run the test
    asyncio.run(test_bot())
