# Wazuh SIEM Analyzer - Full Stack Setup

## 🚀 Quick Start Guide

### Backend Setup (Python Flask)

1. **Install Python dependencies:**
```bash
pip install -r backend_requirements.txt
```

2. **Start the Flask backend:**
```bash
python routes.py
```

The backend will run on `http://localhost:5000`

### Frontend Setup (React + TypeScript)

1. **Navigate to frontend directory:**
```bash
cd frontend
```

2. **Install Node.js dependencies:**
```bash
npm install socket.io-client
```

3. **Start the development server:**
```bash
npm run dev
```

The frontend will run on `http://localhost:5173`

---

## 📋 Backend API Endpoints

### REST Endpoints

- **POST** `/chat` - Send chat messages in normal mode
  ```json
  {
    "message": "Show me failed login attempts"
  }
  ```

- **POST** `/auto_mode` - Toggle auto monitoring mode
  ```json
  {
    "enabled": true
  }
  ```

- **GET** `/health` - Health check endpoint

### WebSocket Events

**Client → Server:**
- `chat_message` - Send chat messages
- `start_auto_mode` - Start auto monitoring
- `stop_auto_mode` - Stop auto monitoring

**Server → Client:**
- `connection_response` - Connection confirmation
- `chat_processing` - Query is being processed
- `chat_response` - AI response ready
- `chat_error` - Error occurred
- `auto_mode_started` - Auto mode activated
- `auto_mode_stopped` - Auto mode deactivated
- `scan_start` - Scan initiated
- `scan_clear` - No threats detected
- `security_alert` - ⚠️ Suspicious activity found
- `scan_error` - Scan error

---

## 🔧 Architecture

```
┌─────────────────┐         WebSocket/HTTP        ┌──────────────────┐
│                 │ ◄────────────────────────────► │                  │
│  React Frontend │                                │  Flask Backend   │
│  (TypeScript)   │                                │  (Python)        │
│                 │                                │                  │
└─────────────────┘                                └────────┬─────────┘
                                                            │
                                                            │
                                                    ┌───────▼────────┐
                                                    │  Wazuh Analyzer│
                                                    │  (AI Engine)   │
                                                    └───────┬────────┘
                                                            │
                                        ┌───────────────────┴───────────────────┐
                                        │                                       │
                                ┌───────▼────────┐                   ┌─────────▼────────┐
                                │ Elasticsearch  │                   │   Groq LLM       │
                                │  (Data Store)  │                   │  (AI Analysis)   │
                                └────────────────┘                   └──────────────────┘
```

---

## 🛠️ Features

### Normal Mode
- Interactive Q&A with AI-powered security analysis
- Real-time Elasticsearch queries
- Intelligent threat analysis

### Auto Mode
- Continuous monitoring every 10 seconds
- Automatic threat detection
- Real-time alerts via WebSocket
- Background scanning with live updates

---

## 🐛 Debugging

### Backend Console Logs
- `[SOCKET]` - WebSocket events
- `[AUTO SCAN]` - Auto mode scanning
- `[CHAT]` - Chat interactions
- Standard Flask logs with timestamps

### Frontend Console Logs
- `[SOCKET]` - WebSocket connection events
- `[AUTO MODE]` - Auto mode state changes
- `[CHAT]` - Message sending/receiving

---

## 📦 Dependencies

### Backend
- Flask - Web framework
- Flask-CORS - Cross-origin support
- Flask-SocketIO - WebSocket support
- Elasticsearch - Data querying
- LangChain + Groq - AI analysis

### Frontend
- React + TypeScript - UI framework
- Socket.IO Client - WebSocket client
- Tailwind CSS - Styling
- Shadcn/ui - UI components

---

## 🔒 Security Notes

- Update the `SECRET_KEY` in `routes.py` for production
- Configure CORS origins appropriately
- Secure Elasticsearch connection
- Use environment variables for API keys
- Enable HTTPS in production

---

## 🎯 Testing

1. Start Elasticsearch (should be running on `localhost:9200`)
2. Populate test data: `python populate_test_data.py`
3. Start backend: `python routes.py`
4. Start frontend: `cd frontend && npm run dev`
5. Open browser: `http://localhost:5173`

---

## 💡 Tips

- Check browser console for WebSocket connection status
- Monitor backend terminal for real-time event logs
- Use auto mode for continuous threat monitoring
- Normal mode for interactive investigations
