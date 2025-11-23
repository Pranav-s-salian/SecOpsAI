#!/usr/bin/env python3
"""
Flask backend routes for Wazuh SIEM Analyzer
Handles chat interactions and auto-monitoring mode with WebSocket support
"""

import asyncio
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, disconnect
from datetime import datetime
import logging
from intelligent_wazuh_analyzer import IntelligentWazuhAnalyzer
from tele_bot import (telegram_bot, start_telegram_bot, stop_telegram_bot, 
                      send_security_alert, get_bot_status, enable_tele_chat_mode, 
                      disable_tele_chat_mode, send_telegram_chat_response)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'wazuh-siem-analyzer-secret-key-2025'
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:5173", "http://localhost:8080", "http://127.0.0.1:5173"],
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "OPTIONS"]
    }
})

# Initialize SocketIO with CORS support
socketio = SocketIO(
    app,
    cors_allowed_origins=["http://localhost:5173", "http://localhost:8080", "http://127.0.0.1:5173"],
    logger=True,
    engineio_logger=True,
    async_mode='threading'
)

# Global analyzer instance
analyzer = None
auto_mode_active = {}  # Track auto mode per client (client_id -> bool)
tele_mode_active = {}  # Track tele/conversation mode per client
scan_cancelled = {}    # Immediate cancellation flags for auto scan tasks
last_client_id = None  # Most recent connected dashboard client

def get_analyzer():
    """Get or create analyzer instance"""
    global analyzer
    if analyzer is None:
        logger.info("Initializing Wazuh Analyzer...")
        analyzer = IntelligentWazuhAnalyzer()
        logger.info(" Analyzer initialized successfully")
    return analyzer


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    logger.info("Health check requested")
    bot_status = get_bot_status()
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'analyzer_ready': analyzer is not None,
        'telegram_bot': bot_status
    })


@app.route('/telegram/status', methods=['GET'])
def telegram_status():
    """Get Telegram bot status"""
    status = get_bot_status()
    return jsonify({
        'status': 'success',
        'telegram': status,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/tele_mode', methods=['POST'])
def tele_mode_toggle():
    """
    Toggle Telegram chat mode
    Expects JSON: { "enabled": true/false }
    """
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        
        logger.info(f"Tele mode toggle request - enabled: {enabled}")
        
        return jsonify({
            'status': 'success',
            'tele_mode': enabled,
            'message': f"Tele mode {'enabled' if enabled else 'disabled'}",
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f" Error toggling tele mode: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/chat', methods=['POST'])
def chat():
    """
    Main chat endpoint - handles user queries in normal mode
    Expects JSON: { "message": "user query here" }
    Returns: { "response": "AI response", "timestamp": "ISO timestamp" }
    """
    try:
        logger.info(" Chat request received")
        
        # Parse request
        data = request.get_json()
        if not data or 'message' not in data:
            logger.warning("Invalid request - missing message")
            return jsonify({
                'error': 'Missing message in request body'
            }), 400
        
        user_message = data['message'].strip()
        logger.info(f" User message: {user_message[:100]}...")
        
        if not user_message:
            logger.warning("⚠️ Empty message received")
            return jsonify({
                'error': 'Message cannot be empty'
            }), 400
        
        # Get analyzer instance
        wazuh_analyzer = get_analyzer()
        
        # Process query asynchronously
        logger.info("🧠 Processing query with AI analyzer...")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            response = loop.run_until_complete(
                wazuh_analyzer.analyze_query(user_message)
            )
            logger.info(f"✅ Query processed successfully - response length: {len(response)} chars")
        finally:
            loop.close()
        
        # Return response
        return jsonify({
            'response': response,
            'timestamp': datetime.now().isoformat(),
            'query': user_message,
            'mode': 'normal'
        })
        
    except Exception as e:
        logger.error(f"❌ Error in chat endpoint: {str(e)}", exc_info=True)
        return jsonify({
            'error': f'Internal server error: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/auto_mode', methods=['POST'])
def auto_mode_toggle():
    """
    Toggle auto monitoring mode
    Expects JSON: { "enabled": true/false }
    """
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        
        logger.info(f"🔄 Auto mode toggle request - enabled: {enabled}")
        
        return jsonify({
            'status': 'success',
            'auto_mode': enabled,
            'message': f"Auto mode {'enabled' if enabled else 'disabled'}",
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"❌ Error toggling auto mode: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e)
        }), 500


# ==================== WebSocket Events ====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    global last_client_id
    client_id = request.sid
    logger.info(f"🔌 Client connected: {client_id}")
    last_client_id = client_id  # Update most recent client for Telegram bridging
    
    emit('connection_response', {
        'status': 'connected',
        'client_id': client_id,
        'timestamp': datetime.now().isoformat(),
        'message': 'Successfully connected to Wazuh SIEM Analyzer'
    })
    
    print(f"[SOCKET] Client {client_id} connected successfully")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    global last_client_id
    client_id = request.sid
    logger.info(f"🔌 Client disconnected: {client_id}")
    
    # Stop auto mode if active
    if client_id in auto_mode_active:
        auto_mode_active[client_id] = False
        del auto_mode_active[client_id]
        logger.info(f"🛑 Auto mode stopped for disconnected client: {client_id}")
    
    # Stop tele mode if active
    if client_id in tele_mode_active:
        tele_mode_active[client_id] = False
        del tele_mode_active[client_id]
        logger.info(f"🛑 Tele mode stopped for disconnected client: {client_id}")
    
    if last_client_id == client_id:
        last_client_id = None
    print(f"[SOCKET] Client {client_id} disconnected")


@socketio.on('start_auto_mode')
def handle_start_auto_mode(data):
    """Start auto monitoring mode for this client"""
    client_id = request.sid
    logger.info(f"🚀 Starting auto mode for client: {client_id}")
    print(f"[SOCKET] Auto mode START requested by {client_id}")
    
    if client_id in auto_mode_active and auto_mode_active[client_id]:
        logger.warning(f"⚠️ Auto mode already running for client: {client_id}")
        emit('auto_mode_error', {
            'error': 'Auto mode already running',
            'timestamp': datetime.now().isoformat()
        })
        return
    
    # Start Telegram bot if not already running
    if not telegram_bot.is_running:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            bot_started = loop.run_until_complete(start_telegram_bot())
            if bot_started:
                logger.info("✅ Telegram bot started successfully")
                # Notify user about Telegram bot
                emit('telegram_notification', {
                    'status': 'available',
                    'message': '📱 Telegram notifications enabled! Send /start to @SecOpsAIBot to receive alerts.',
                    'bot_token': '8404982146:AAFFGR9QKaqpiKJ2vYcmL_IKCIebzYykUiQ',
                    'instructions': 'Open Telegram and search for @SecOpsAIBot, then send /start to activate alerts.'
                })
        except Exception as e:
            logger.error(f"Failed to start Telegram bot: {e}")
        finally:
            loop.close()
    
    # Mark auto mode as active
    auto_mode_active[client_id] = True
    
    # Get bot status
    bot_status = get_bot_status()
    
    # Send confirmation
    emit('auto_mode_started', {
        'status': 'started',
        'timestamp': datetime.now().isoformat(),
        'message': 'Auto monitoring mode activated - scanning every 10 seconds',
        'telegram_active': bot_status['running'],
        'telegram_subscribers': bot_status['active_users']
    })
    
    print(f"[SOCKET] Auto mode started for {client_id}")
    
    # Start auto scanning in background
    socketio.start_background_task(run_auto_scan, client_id)


@socketio.on('stop_auto_mode')
def handle_stop_auto_mode(data):
    """Stop auto monitoring mode for this client"""
    client_id = request.sid
    logger.info(f"🛑 Stopping auto mode for client: {client_id}")
    print(f"[SOCKET] Auto mode STOP requested by {client_id}")
    
    if client_id in auto_mode_active:
        auto_mode_active[client_id] = False
        del auto_mode_active[client_id]
    
    emit('auto_mode_stopped', {
        'status': 'stopped',
        'timestamp': datetime.now().isoformat(),
        'message': 'Auto monitoring mode deactivated'
    })
    
    print(f"[SOCKET] Auto mode stopped for {client_id}")


async def telegram_chat_callback(message, chat_id, username, is_command=False):
    """Global Telegram callback.
    - /auto: start background scanning (dashboard if present, else telegram-only)
    - /conversation: enable interactive chat (AI responses to each message)
    - Regular message: analyze only if conversation mode active
    """
    global last_client_id
    client_id = last_client_id  # Use latest dashboard client if available
    print(f"[TELE CHAT] {'COMMAND' if is_command else 'MSG'} from @{username}: {message}")

    if is_command:
        if message == "/auto":
            # Switch to auto mode (disable conversation)
            telegram_bot.disable_tele_mode()
            if client_id:
                tele_mode_active.pop(client_id, None)
                auto_mode_active[client_id] = True
                socketio.emit('auto_mode_started', {
                    'status': 'started',
                    'timestamp': datetime.now().isoformat(),
                    'message': 'Auto Mode activated via Telegram',
                    'triggered_by': f'telegram_user_{username}'
                }, room=client_id)
                socketio.start_background_task(run_auto_scan, client_id)
                return "Auto Mode activated. You will receive alerts only when threats are detected."
            else:
                # Telegram-only scanning
                auto_mode_active[None] = True
                socketio.start_background_task(run_auto_scan, None)
                return "Auto Mode activated (telegram-only). Alerts will arrive on threats."

        if message == "/conversation":
            # Enable conversation mode (stop any active auto scans immediately)
            telegram_bot.enable_tele_mode(telegram_chat_callback)
            
            # Force cancel ALL scans
            scan_cancelled[None] = True
            if client_id:
                scan_cancelled[client_id] = True
            for cid in list(auto_mode_active.keys()):
                scan_cancelled[cid] = True
                
            # Clear auto mode active flags
            auto_mode_active.clear()
            
            # Emit auto_mode_stopped if dashboard client present
            if client_id:
                socketio.emit('auto_mode_stopped', {
                    'status': 'stopped',
                    'timestamp': datetime.now().isoformat(),
                    'message': 'Auto monitoring mode deactivated (switched to Conversation Mode)'
                }, room=client_id)
                tele_mode_active[client_id] = True
                socketio.emit('tele_mode_started', {
                    'status': 'started',
                    'timestamp': datetime.now().isoformat(),
                    'message': 'Conversation Mode activated via Telegram',
                    'triggered_by': f'telegram_user_{username}'
                }, room=client_id)
            
            # Ensure telegram_bot tele_mode_active is updated
            telegram_bot.tele_mode_active = True
            logger.info("[TELEGRAM] Conversation Mode activated in bot instance.")
            return "Conversation Mode activated. Send your questions now." 

    # Non-command path
    if not telegram_bot.tele_mode_active:
        return "⚠️ Conversation Mode not active. Send /conversation first."

    # Forward message to dashboard if present
    if client_id:
        socketio.emit('telegram_message', {
            'message': message,
            'username': username,
            'chat_id': chat_id,
            'timestamp': datetime.now().isoformat()
        }, room=client_id)

    wazuh_analyzer = get_analyzer()
    # No need for new event loop here as we are already in one (called from tele_bot)
    try:
        try:
            response = await wazuh_analyzer.analyze_query(message)
        except Exception as e:
            response = f"**ERROR** processing query: {e}"
        
        await send_telegram_chat_response(chat_id, f"🤖 **SecurAI Response:**\n\n{response}")
        
        if client_id:
            socketio.emit('telegram_response', {
                'response': response,
                'query': message,
                'username': username,
                'timestamp': datetime.now().isoformat()
            }, room=client_id)
            
    except Exception as e:
        logger.error(f"Error in telegram chat callback: {e}")
        await send_telegram_chat_response(chat_id, "❌ An error occurred while processing your request.")
        return f"Error: {e}"
        
    return response


@socketio.on('start_tele_mode')
def handle_start_tele_mode(data):
    """Start Telegram chat mode for this client"""
    client_id = request.sid
    logger.info(f"📱 Starting Tele mode for client: {client_id}")
    print(f"[SOCKET] Tele mode START requested by {client_id}")
    
    if client_id in tele_mode_active and tele_mode_active[client_id]:
        logger.warning(f"⚠️ Tele mode already running for client: {client_id}")
        emit('tele_mode_error', {
            'error': 'Tele mode already running',
            'timestamp': datetime.now().isoformat()
        })
        return
    
    # Mark tele mode as active
    tele_mode_active[client_id] = True
    
    # Enable Telegram chat mode with global callback
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(enable_tele_chat_mode(telegram_chat_callback))
    finally:
        loop.close()
    
    # Send confirmation
    emit('tele_mode_started', {
        'status': 'started',
        'timestamp': datetime.now().isoformat(),
        'message': 'Tele Mode activated - Users can now chat via Telegram!'
    })
    
    print(f"[SOCKET] Tele mode started for {client_id}")


@socketio.on('stop_tele_mode')
def handle_stop_tele_mode(data):
    """Stop Telegram chat mode for this client"""
    client_id = request.sid
    logger.info(f"🛑 Stopping Tele mode for client: {client_id}")
    print(f"[SOCKET] Tele mode STOP requested by {client_id}")
    
    if client_id in tele_mode_active:
        tele_mode_active[client_id] = False
        del tele_mode_active[client_id]
    
    # Disable Telegram chat mode
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(disable_tele_chat_mode())
    finally:
        loop.close()
    
    emit('tele_mode_stopped', {
        'status': 'stopped',
        'timestamp': datetime.now().isoformat(),
        'message': 'Tele Mode deactivated'
    })
    
    print(f"[SOCKET] Tele mode stopped for {client_id}")


@socketio.on('chat_message')
def handle_chat_message(data):
    """Handle chat messages through WebSocket"""
    client_id = request.sid
    message = data.get('message', '').strip()
    
    logger.info(f"💬 WebSocket chat message from {client_id}: {message[:100]}...")
    print(f"[SOCKET] Chat message from {client_id}: {message}")
    
    if not message:
        emit('chat_error', {
            'error': 'Message cannot be empty',
            'timestamp': datetime.now().isoformat()
        })
        return
    
    try:
        # Get analyzer
        wazuh_analyzer = get_analyzer()
        
        # Send processing status
        emit('chat_processing', {
            'status': 'processing',
            'query': message,
            'timestamp': datetime.now().isoformat()
        })
        
        print(f"[SOCKET] Processing query: {message}")
        
        # Process query
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            response = loop.run_until_complete(
                wazuh_analyzer.analyze_query(message)
            )
            print(f"[SOCKET] Query processed - response length: {len(response)} chars")
        finally:
            loop.close()
        
        # Send response
        emit('chat_response', {
            'response': response,
            'query': message,
            'timestamp': datetime.now().isoformat()
        })
        
        print(f"[SOCKET] Response sent to {client_id}")
        
    except Exception as e:
        logger.error(f"❌ Error processing WebSocket message: {str(e)}", exc_info=True)
        print(f"[SOCKET ERROR] {str(e)}")
        
        emit('chat_error', {
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        })


def run_auto_scan(client_id):
    """
    Background task to run auto scanning every 10 seconds
    Emits results to specific client via WebSocket
    """
    logger.info(f"🔄 Auto scan background task started for client: {client_id}")
    print(f"[AUTO SCAN] Background task started for {client_id}")
    
    scan_count = 0
    wazuh_analyzer = get_analyzer()
    
    # Create event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Support telegram-only mode (client_id may be None)
        while (client_id is None and None in auto_mode_active and auto_mode_active[None]) or (client_id in auto_mode_active and auto_mode_active[client_id]):
            if client_id in scan_cancelled or (client_id is None and None in scan_cancelled):
                print(f"[AUTO SCAN] Cancellation flag detected for {client_id}. Exiting scan loop immediately.")
                break
            scan_count += 1
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            logger.info(f"🔍 Auto scan #{scan_count} for client {client_id}")
            print(f"[AUTO SCAN] Scan #{scan_count} started at {current_time}")
            
            # Emit scan start
            if client_id is not None:
                socketio.emit('scan_start', {
                    'scan_number': scan_count,
                    'timestamp': current_time,
                    'message': f'Scan #{scan_count} - Checking for threats...'
                }, room=client_id)
            
            try:
                # Perform security scan
                suspicious_findings = loop.run_until_complete(
                    wazuh_analyzer._perform_auto_security_scan()
                )
                # Mid-scan cancellation check
                if client_id in scan_cancelled or (client_id is None and None in scan_cancelled):
                    print(f"[AUTO SCAN] Cancellation flag detected mid-scan for {client_id}. Aborting before reporting.")
                    break
                
                print(f"[AUTO SCAN] Scan completed - suspicious items: {suspicious_findings.get('total_suspicious', 0)}")
                
                if suspicious_findings and suspicious_findings.get("total_suspicious", 0) > 0:
                    # ALERT! Suspicious activity detected
                    logger.warning(f"🚨 ALERT! Suspicious activity detected in scan #{scan_count}")
                    print(f"[AUTO SCAN] 🚨 ALERT! Suspicious activity found!")
                    
                    # Format alert message
                    alert_message = loop.run_until_complete(
                        wazuh_analyzer._format_auto_scan_alert(suspicious_findings)
                    )
                    
                    # Send alert to Telegram if bot is active
                    try:
                        loop.run_until_complete(send_security_alert(suspicious_findings))
                        print(f"[AUTO SCAN] 📱 Alert sent to Telegram subscribers")
                    except Exception as telegram_error:
                        logger.error(f"Failed to send Telegram alert: {telegram_error}")
                    
                    # Emit alert to client
                    if client_id is not None:
                        socketio.emit('security_alert', {
                            'scan_number': scan_count,
                            'timestamp': current_time,
                            'alert': alert_message,
                            'findings': suspicious_findings,
                            'severity': 'high',
                            'telegram_sent': telegram_bot.is_active()
                        }, room=client_id)
                        print(f"[AUTO SCAN] Alert emitted to client {client_id}")
                    
                else:
                    # All clear
                    logger.info(f"✅ Scan #{scan_count} - All clear")
                    print(f"[AUTO SCAN] ✅ All clear")
                    
                    if client_id is not None:
                        socketio.emit('scan_clear', {
                            'scan_number': scan_count,
                            'timestamp': current_time,
                            'message': f'Scan #{scan_count} - All clear, no threats detected'
                        }, room=client_id)
                
            except Exception as scan_error:
                logger.error(f"❌ Error in scan #{scan_count}: {str(scan_error)}")
                print(f"[AUTO SCAN ERROR] {str(scan_error)}")
                
                if client_id is not None:
                    socketio.emit('scan_error', {
                        'scan_number': scan_count,
                        'timestamp': current_time,
                        'error': str(scan_error)
                    }, room=client_id)
            
            # Wait 10 seconds before next scan
            for _ in range(10):
                if client_id in scan_cancelled or (client_id is None and None in scan_cancelled):
                    print(f"[AUTO SCAN] Cancellation flag detected during sleep for {client_id}. Exiting.")
                    break
                socketio.sleep(1)
            if client_id in scan_cancelled or (client_id is None and None in scan_cancelled):
                break
            
    except Exception as e:
        logger.error(f"Auto scan background task error: {str(e)}", exc_info=True)
        print(f"[AUTO SCAN FATAL ERROR] {str(e)}")
    finally:
        loop.close()
        # Cleanup cancellation and active mode entries
        if client_id is None:
            auto_mode_active.pop(None, None)
            scan_cancelled.pop(None, None)
        else:
            auto_mode_active.pop(client_id, None)
            scan_cancelled.pop(client_id, None)
        logger.info(f" Auto scan task ended for client: {client_id}")
        print(f"[AUTO SCAN] Background task ended for {client_id}")




@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 Not Found: {request.url}")
    return jsonify({
        'error': 'Endpoint not found',
        'path': request.path
    }), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f" 500 Internal Server Error: {str(error)}")
    return jsonify({
        'error': 'Internal server error',
        'message': str(error)
    }), 500


# ==================== Main Entry Point ====================

if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  WAZUH SIEM ANALYZER - FLASK BACKEND")
    print("=" * 70)
    print("🚀 Starting Flask server with WebSocket support...")
    print("📡 Server will be available at: http://localhost:5000")
    print("🔌 WebSocket endpoint: ws://localhost:5000/socket.io")
    print("=" * 70)
    print("\n📋 Available Routes:")
    print("   • POST /chat - Normal chat interaction")
    print("   • POST /auto_mode - Toggle auto monitoring")
    print("   • POST /tele_mode - Toggle Telegram chat mode")
    print("   • GET  /health - Health check")
    print("   • GET  /telegram/status - Telegram bot status")
    print("\n🔌 WebSocket Events:")
    print("   • start_auto_mode - Start auto scanning")
    print("   • stop_auto_mode - Stop auto scanning")
    print("   • start_tele_mode - Enable Telegram chat")
    print("   • stop_tele_mode - Disable Telegram chat")
    print("   • chat_message - Send chat message")
    print("=" * 70)
    print()
    
    # Initialize analyzer on startup
    get_analyzer()
    
    # Start Telegram bot in background
    print("📱 Starting Telegram bot in background...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        bot_started = loop.run_until_complete(start_telegram_bot())
        if bot_started:
            print("✅ Telegram bot started successfully!")
            print("📱 Users can now send /start to the bot to receive alerts")
            
            # Register global callback for Telegram messages
            loop.run_until_complete(enable_tele_chat_mode(telegram_chat_callback))
            print("✅ Telegram command handler registered")
        else:
            print("⚠️  Telegram bot failed to start (alerts will be disabled)")
    except Exception as e:
        print(f"⚠️  Telegram bot initialization failed: {e}")
        print("   Continuing without Telegram alerts...")
    finally:
        loop.close()
    
    print("=" * 70)
    print()
    
    # Run Flask app with SocketIO
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=False  # Disable reloader to prevent double initialization
    )
