# Intelligent Wazuh SIEM Analyzer - Architecture Analysis

## 🏗️ System Overview

This is an **AI-powered Security Information and Event Management (SIEM) analysis system** that bridges natural language queries with structured security data from Wazuh and Elasticsearch.

### Core Concept
The system works like a **3-layer intelligence sandwich**:
1. **Top Layer (AI Brain)**: Groq LLM understands what you're asking
2. **Middle Layer (Orchestrator)**: Intelligent query router and executor
3. **Bottom Layer (Data Sources)**: Elasticsearch (logs) + Wazuh MCP Server (agent data)

---

## 📊 Architecture Components

### 1. **Intelligent Wazuh Analyzer** (`intelligent_wazuh_analyzer.py`)
**Role**: Main orchestration engine that coordinates everything

**Key Responsibilities**:
- Accept natural language security questions from users
- Use AI (Groq LLM) to understand query intent
- Build intelligent execution plans
- Query Elasticsearch for security events
- Call Wazuh MCP Server for agent/system data
- Format responses with AI-generated insights

**Flow**:
```
User Query → AI Analysis → Execution Plan → Data Retrieval → AI Formatting → Response
```

### 2. **Wazuh MCP Server** (`wazuh-mcp-server/`)
**Role**: Middleware adapter between the analyzer and Wazuh Manager API

**Key Components**:
- **`server.py`**: FastMCP server exposing Wazuh tools as MCP endpoints
- **`client.py`**: Async HTTP client handling Wazuh API authentication & requests
- **`config.py`**: Configuration management for server/Wazuh connection

**Available Tools** (exposed as MCP tools):
- `AuthenticateTool`: Get JWT token from Wazuh
- `GetAgentsTool`: List all Wazuh agents
- `GetAgentPortsTool`: Get network ports for an agent
- `GetAgentPackagesTool`: Get installed packages
- `GetAgentProcessesTool`: Get running processes
- `ListRulesTool`: Get Wazuh detection rules
- `GetAgentSCATool`: Get security compliance assessment results
- `GetSCAPolicyChecksTool`: Get detailed SCA policy checks
- `GetRuleFileContentTool`: Get rule file XML content
- `GetRuleFilesTool`: List all rule files

### 3. **Elasticsearch**
**Role**: Primary data store for security events and logs

**Indices**:
- `wazuh-alerts-*`: Security alerts and events
- `wazuh-archives-*`: Archived events
- `filebeat-*`: Log collection data

**Query Types**:
- Authentication events (failed/successful logins, SSH, brute force)
- Security alerts (malware, attacks, high-severity incidents)
- Network events
- Compliance violations

### 4. **Groq LLM** (llama-3.3-70b-versatile)
**Role**: AI reasoning engine

**Two Key Functions**:
1. **Query Analysis**: Understands user intent and extracts parameters
   - Intent classification (authentication, network, agents, alerts, etc.)
   - Entity extraction (IPs, usernames, time ranges, severity levels)
   - Approach selection (Elasticsearch vs Wazuh API)

2. **Response Formatting**: Generates intelligent security insights
   - Executive summaries
   - Risk assessments
   - Security recommendations
   - Contextual explanations

---

## 🔄 Data Flow Architecture

### High-Level Flow

```
┌─────────────┐
│    User     │
│   (Human)   │
└──────┬──────┘
       │ Natural Language Query
       │ "Show me failed logins from yesterday"
       ▼
┌─────────────────────────────────────────┐
│  Intelligent Wazuh Analyzer             │
│  ┌────────────────────────────────┐     │
│  │ 1. AI Query Analysis (Groq)   │     │
│  │    - Detect intent             │     │
│  │    - Extract entities          │     │
│  │    - Choose approach           │     │
│  └────────────────────────────────┘     │
│              │                           │
│              ▼                           │
│  ┌────────────────────────────────┐     │
│  │ 2. Execution Plan Creation     │     │
│  │    - Elasticsearch queries?    │     │
│  │    - Wazuh API calls?          │     │
│  │    - Both (hybrid)?            │     │
│  └────────────────────────────────┘     │
│              │                           │
│              ▼                           │
│  ┌────────────────────────────────┐     │
│  │ 3. Parallel Data Retrieval     │     │
│  └────────────────────────────────┘     │
└────────┬─────────────────────┬──────────┘
         │                     │
         │                     │
    ┌────▼──────┐         ┌───▼──────────┐
    │Elasticsearch│         │ Wazuh MCP   │
    │             │         │   Server    │
    │ - Auth logs│         │             │
    │ - Alerts   │         │ ┌─────────┐ │
    │ - Events   │         │ │ Client  │ │
    │            │         │ │ (HTTP)  │ │
    │ DSL Queries│         │ └────┬────┘ │
    └────────────┘         │      │      │
                           │      ▼      │
                           │ ┌─────────┐ │
                           │ │ Wazuh   │ │
                           │ │ Manager │ │
                           │ │   API   │ │
                           │ └─────────┘ │
                           └─────────────┘
         │                     │
         │ JSON Results        │ JSON Results
         │                     │
         └────────┬────────────┘
                  ▼
    ┌──────────────────────────┐
    │ 4. Result Aggregation    │
    │    - Merge data          │
    │    - Extract key metrics │
    └──────────┬───────────────┘
               │
               ▼
    ┌──────────────────────────┐
    │ 5. AI Formatting (Groq)  │
    │    - Security analysis   │
    │    - Risk assessment     │
    │    - Recommendations     │
    └──────────┬───────────────┘
               │
               ▼
         ┌─────────┐
         │  User   │
         │Response │
         └─────────┘
```

---

## 🧠 AI Intelligence Layers

### Layer 1: Query Understanding
```python
Input: "Show me failed login attempts from yesterday"

AI Analysis Output:
{
  "intent": "authentication",
  "sub_intent": "failed login analysis",
  "action_type": "failed",
  "time_range": "yesterday",
  "entities": {
    "ip_addresses": [],
    "usernames": [],
    "severity": "medium"
  },
  "confidence": "high",
  "approach": "elasticsearch_primary"
}
```

### Layer 2: Query Execution
The analyzer converts AI analysis into:
1. **Elasticsearch DSL Query**:
```json
{
  "query": {
    "bool": {
      "must": [],
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2025-11-14T00:00:00",
              "lte": "2025-11-14T23:59:59"
            }
          }
        }
      ],
      "should": [
        {"match": {"rule.groups": "authentication_failed"}},
        {"match": {"rule.groups": "sshd"}},
        {"match": {"rule.description": "failed"}}
      ],
      "minimum_should_match": 1
    }
  }
}
```

2. **MCP Server Call** (if needed for agent info):
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "GetAgentsTool",
    "arguments": {"status": ["active"]}
  }
}
```

### Layer 3: Response Intelligence
```python
Raw Data: 35 failed login events found

AI Generated Analysis:
"""
🔍 SECURITY ANALYSIS

Found 35 failed authentication attempts from yesterday:
- 20 attempts from IP 192.168.1.99 (BRUTE FORCE PATTERN)
- Targeting accounts: root (15), admin (5)
- Time window: 2-minute intervals (automated attack signature)

⚠️ RISK ASSESSMENT: HIGH
This pattern indicates an active brute force attack.

🛡️ RECOMMENDATIONS:
1. Block IP 192.168.1.99 immediately
2. Implement fail2ban or rate limiting
3. Review compromised account security
4. Enable MFA for admin accounts
"""
```

---

## 🗂️ Code Architecture

### Class Hierarchy

```
IntelligentWazuhAnalyzer
├── __init__()                      # Initialize ES + Groq LLM
├── analyze_query()                 # Main entry point
├── _analyze_query_with_ai()        # AI query understanding
├── _fallback_query_analysis()      # Keyword-based fallback
├── _create_execution_plan()        # Build execution strategy
├── _execute_plan()                 # Execute all steps
├── _execute_elasticsearch_query()  # ES query execution
├── _call_wazuh_tool()             # MCP server communication
├── _format_detailed_response()     # AI-powered formatting
├── _build_auth_elasticsearch_query()  # DSL query builder
└── _build_alerts_elasticsearch_query() # Alert query builder

WazuhMCPServer (in wazuh-mcp-server/)
├── __init__()                      # Initialize FastMCP app
├── _register_tools()               # Register all MCP tools
├── _get_client()                   # Get/create Wazuh client
└── start()                         # Start uvicorn server

WazuhClient
├── __init__()                      # Setup HTTP client
├── _refresh_token()                # JWT authentication
├── request()                       # Authenticated API calls
├── get_agents()                    # Retrieve agents
├── get_agent_ports()               # Get network ports
├── get_agent_packages()            # Get packages
├── list_rules()                    # Get detection rules
└── ... (other methods)
```

---

## 🔐 Security Flow Example

Let's trace a real query: **"Show me failed login attempts from yesterday"**

### Step-by-Step Execution

1. **User Input** → Analyzer receives query

2. **AI Analysis** (Groq LLM)
   - Intent: `authentication`
   - Action: `failed`
   - Time: `yesterday`
   - Approach: `elasticsearch_primary`

3. **Execution Plan Creation**
   ```python
   plan = {
     "steps": [
       {
         "action": "query_elasticsearch",
         "target": "authentication_events",
         "params": {
           "time_range": "yesterday",
           "action_type": "failed"
         }
       }
     ]
   }
   ```

4. **Elasticsearch Query Execution**
   - Connects to `http://localhost:9200`
   - Searches indices: `wazuh-alerts-*`
   - Applies time filter (yesterday 00:00 - 23:59)
   - Matches authentication + failed patterns
   - Returns 35 events

5. **Result Processing**
   - Extract event details: timestamps, IPs, users, descriptions
   - Count patterns: IP frequency, user attempts
   - Calculate metrics: total events, unique IPs

6. **AI Formatting** (Groq LLM)
   - Analyzes patterns (brute force detection)
   - Assesses security implications
   - Generates recommendations
   - Formats human-readable report

7. **Display to User**
   - Findings summary (35 events)
   - Detailed sample events
   - Intelligent analysis
   - Security recommendations

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **AI Engine** | Groq (llama-3.3-70b) | Query understanding & response generation |
| **Orchestrator** | Python AsyncIO | Async coordination of queries |
| **Data Store** | Elasticsearch | Security event storage & search |
| **Middleware** | FastMCP (FastAPI-based) | MCP protocol server |
| **API Client** | httpx (async) | HTTP communication with Wazuh |
| **SIEM Platform** | Wazuh Manager | Security monitoring & agent management |
| **Protocol** | MCP (Model Context Protocol) | Tool-calling standard |
| **Authentication** | JWT (JSON Web Tokens) | Wazuh API security |

---

## 🔗 Communication Protocols

### 1. **User ↔ Analyzer**
- **Protocol**: Interactive CLI (stdin/stdout)
- **Format**: Plain text questions → Markdown formatted responses

### 2. **Analyzer ↔ Groq LLM**
- **Protocol**: HTTPS REST API
- **Format**: JSON prompts → JSON/text responses
- **Library**: `langchain_groq.ChatGroq`

### 3. **Analyzer ↔ Elasticsearch**
- **Protocol**: HTTP REST API
- **Format**: Elasticsearch DSL (JSON)
- **Library**: `elasticsearch-py`
- **Port**: 9200

### 4. **Analyzer ↔ Wazuh MCP Server**
- **Protocol**: JSON-RPC 2.0 over HTTP
- **Format**: MCP tool call requests/responses
- **Library**: `httpx` (async)
- **Port**: 8010 (configurable)

### 5. **MCP Server ↔ Wazuh Manager**
- **Protocol**: HTTPS REST API
- **Format**: JSON requests/responses
- **Authentication**: JWT Bearer tokens
- **Library**: `httpx` with HTTP/2

---

## 🎯 Key Design Patterns

### 1. **Strategy Pattern**
- Different execution strategies based on query intent
- Elasticsearch-primary vs Wazuh-primary vs Hybrid

### 2. **Adapter Pattern**
- MCP Server adapts Wazuh API to MCP protocol
- Makes Wazuh tools accessible as standardized MCP tools

### 3. **Pipeline Pattern**
- Query flows through stages: Analysis → Planning → Execution → Formatting
- Each stage transforms data for next stage

### 4. **Factory Pattern**
- Query builders (`_build_auth_elasticsearch_query`, `_build_alerts_elasticsearch_query`)
- Dynamic creation of ES DSL queries

### 5. **Facade Pattern**
- `IntelligentWazuhAnalyzer` hides complexity of multiple systems
- Simple interface: `analyze_query(text)` → formatted response

---

## 💡 Intelligence Features

### 1. **Natural Language Understanding**
- No need for DSL or query syntax
- "Show me" / "Find" / "Analyze" / "Who" queries
- Time expressions: "yesterday", "last hour", "last week"

### 2. **Context-Aware Analysis**
- Understands security context (brute force, attacks, compliance)
- Extracts entities (IPs, usernames, agent IDs)
- Correlates multiple data sources

### 3. **Intelligent Query Routing**
- Elasticsearch for log/event analysis
- Wazuh API for agent/system information
- Hybrid approach when both needed

### 4. **AI-Powered Insights**
- Not just data display, but analysis
- Risk assessment and severity evaluation
- Actionable security recommendations
- Pattern detection (e.g., brute force identification)

### 5. **Graceful Degradation**
- If AI fails: keyword-based fallback analysis
- If Elasticsearch unavailable: Wazuh-only mode
- If MCP server offline: Elasticsearch-only mode

---

## 🚀 Scalability Considerations

### Current Architecture
- Single-threaded analyzer (async I/O)
- Direct ES and MCP connections
- In-memory result processing

### Potential Improvements
1. **Horizontal Scaling**
   - Multiple analyzer instances behind load balancer
   - Stateless design enables easy scaling

2. **Caching Layer**
   - Redis for AI analysis results
   - Reduce duplicate LLM calls for similar queries

3. **Queue System**
   - RabbitMQ/Kafka for async query processing
   - Handle high query volumes

4. **Result Pagination**
   - Currently limits to 100 results per index
   - Could implement cursor-based pagination

---

## 🎓 Learning Path

To understand this system:
1. Start with `main()` in `intelligent_wazuh_analyzer.py`
2. Follow `analyze_query()` flow
3. Understand AI analysis in `_analyze_query_with_ai()`
4. See how execution plans are built
5. Examine Elasticsearch query builders
6. Explore MCP server tool registration
7. Study Wazuh client API methods

---

## 📝 Configuration

### Required Environment
- Elasticsearch running on `localhost:9200`
- Wazuh MCP Server on `localhost:8010` (optional)
- Groq API key configured
- Python 3.8+ with async support

### Key Files
- `.env`: Wazuh credentials, server config
- `pyproject.toml`: Dependencies and package metadata
- `config.py`: Configuration classes

---

This architecture provides a **powerful, AI-enhanced security analysis platform** that bridges the gap between human security questions and complex technical data sources!
