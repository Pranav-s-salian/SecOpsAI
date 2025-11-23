# Mermaid Architecture Diagrams

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "User Interface"
        User[👤 Security Analyst]
    end
    
    subgraph "AI Layer"
        Groq[🧠 Groq LLM<br/>llama-3.3-70b]
    end
    
    subgraph "Orchestration Layer"
        Analyzer[🎯 Intelligent Wazuh Analyzer<br/>Main Intelligence Engine]
        
        Analyzer -->|1. Query Analysis| AI_Analysis[AI Query Analyzer]
        Analyzer -->|2. Planning| Planner[Execution Planner]
        Analyzer -->|3. Execution| Executor[Query Executor]
        Analyzer -->|4. Formatting| Formatter[Response Formatter]
    end
    
    subgraph "Data Sources"
        ES[🔍 Elasticsearch<br/>Port 9200<br/>Security Events & Logs]
        MCP[🔧 Wazuh MCP Server<br/>Port 8010<br/>FastMCP]
        
        MCP -->|HTTP/2 REST API| WazuhAPI[Wazuh Manager API<br/>JWT Auth]
    end
    
    User -->|Natural Language Query| Analyzer
    
    AI_Analysis -->|Intent Extraction| Groq
    Groq -->|Structured Analysis| AI_Analysis
    
    Formatter -->|Generate Insights| Groq
    Groq -->|Security Analysis| Formatter
    
    Executor -->|DSL Queries| ES
    ES -->|JSON Events| Executor
    
    Executor -->|JSON-RPC Calls| MCP
    MCP -->|Tool Results| Executor
    
    Analyzer -->|Formatted Report| User
    
    style User fill:#e1f5ff
    style Groq fill:#ffe1e1
    style Analyzer fill:#fff4e1
    style ES fill:#e1ffe1
    style MCP fill:#f0e1ff
    style WazuhAPI fill:#f0e1ff
```

## 2. Detailed Query Flow

```mermaid
sequenceDiagram
    participant User
    participant Analyzer as Intelligent Analyzer
    participant Groq as Groq LLM
    participant ES as Elasticsearch
    participant MCP as MCP Server
    participant Wazuh as Wazuh Manager

    User->>Analyzer: "Show me failed logins from yesterday"
    
    rect rgb(255, 240, 240)
        Note over Analyzer,Groq: Step 1: AI Query Analysis
        Analyzer->>Groq: Analyze query intent & entities
        Groq-->>Analyzer: {"intent": "authentication", "action": "failed", "time": "yesterday"}
    end
    
    rect rgb(240, 255, 240)
        Note over Analyzer: Step 2: Create Execution Plan
        Analyzer->>Analyzer: Build query plan<br/>(Elasticsearch primary)
    end
    
    rect rgb(240, 240, 255)
        Note over Analyzer,Wazuh: Step 3: Execute Plan
        
        par Parallel Data Retrieval
            Analyzer->>ES: Search wazuh-alerts-*<br/>DSL Query with time & auth filters
            ES-->>Analyzer: 35 events found
        and Optional Agent Info
            Analyzer->>MCP: Call GetAgentsTool
            MCP->>Wazuh: GET /agents (JWT Auth)
            Wazuh-->>MCP: Agent data
            MCP-->>Analyzer: Agent info
        end
    end
    
    rect rgb(255, 255, 240)
        Note over Analyzer,Groq: Step 4: AI Formatting
        Analyzer->>Groq: Format results with security insights
        Groq-->>Analyzer: Intelligent analysis + recommendations
    end
    
    Analyzer-->>User: 📊 Formatted Security Report
```

## 3. Component Architecture

```mermaid
graph LR
    subgraph "intelligent_wazuh_analyzer.py"
        Main[main Function]
        Analyzer[IntelligentWazuhAnalyzer Class]
        
        Main --> Analyzer
        
        Analyzer --> QueryAI[_analyze_query_with_ai]
        Analyzer --> Fallback[_fallback_query_analysis]
        Analyzer --> CreatePlan[_create_execution_plan]
        Analyzer --> ExecutePlan[_execute_plan]
        Analyzer --> ExecES[_execute_elasticsearch_query]
        Analyzer --> CallMCP[_call_wazuh_tool]
        Analyzer --> Format[_format_detailed_response]
        Analyzer --> BuildAuth[_build_auth_elasticsearch_query]
        Analyzer --> BuildAlert[_build_alerts_elasticsearch_query]
    end
    
    subgraph "wazuh_mcp_server/"
        Server[server.py<br/>WazuhMCPServer]
        Client[client.py<br/>WazuhClient]
        Config[config.py<br/>Config Classes]
        
        Server --> Client
        Server --> Config
    end
    
    QueryAI -.->|Uses| GroqLLM[Groq LLM API]
    Format -.->|Uses| GroqLLM
    
    ExecES -.->|Queries| ESCluster[Elasticsearch]
    CallMCP -.->|JSON-RPC| Server
    Client -.->|REST API| WazuhMgr[Wazuh Manager]
    
    style Analyzer fill:#ffebcc
    style Server fill:#ccebff
    style Client fill:#ccebff
```

## 4. Data Flow Architecture

```mermaid
flowchart TD
    Start([User Query]) --> AIAnalysis{AI Analysis<br/>Groq LLM}
    
    AIAnalysis -->|Success| StructuredIntent[Structured Intent<br/>+ Entities]
    AIAnalysis -->|Failure| KeywordFallback[Keyword Fallback<br/>Analysis]
    
    KeywordFallback --> StructuredIntent
    
    StructuredIntent --> PlanBuilder[Execution Plan Builder]
    
    PlanBuilder --> IntentCheck{Query Intent?}
    
    IntentCheck -->|Authentication| ESAuthQuery[Elasticsearch<br/>Auth Events Query]
    IntentCheck -->|Agents| MCPAgentsCall[MCP Server<br/>GetAgentsTool]
    IntentCheck -->|Network| MCPPortsCall[MCP Server<br/>GetAgentPortsTool]
    IntentCheck -->|Alerts| ESAlertQuery[Elasticsearch<br/>Security Alerts Query]
    IntentCheck -->|Hybrid| BothSources[Both ES + MCP]
    
    ESAuthQuery --> ResultAgg[Result Aggregation]
    MCPAgentsCall --> ResultAgg
    MCPPortsCall --> ResultAgg
    ESAlertQuery --> ResultAgg
    BothSources --> ResultAgg
    
    ResultAgg --> AIFormat{AI Formatting<br/>Available?}
    
    AIFormat -->|Yes| GroqFormat[Groq LLM<br/>Generate Insights]
    AIFormat -->|No| FallbackFormat[Fallback<br/>Structured Format]
    
    GroqFormat --> FinalReport[📊 Final Security Report]
    FallbackFormat --> FinalReport
    
    FinalReport --> End([Display to User])
    
    style AIAnalysis fill:#ffe6e6
    style GroqFormat fill:#ffe6e6
    style ESAuthQuery fill:#e6ffe6
    style ESAlertQuery fill:#e6ffe6
    style MCPAgentsCall fill:#e6e6ff
    style MCPPortsCall fill:#e6e6ff
    style FinalReport fill:#fff4e6
```

## 5. MCP Server Tool Registry

```mermaid
graph TB
    subgraph "Wazuh MCP Server"
        FastMCP[FastMCP Application<br/>uvicorn + SSE]
        
        FastMCP --> Tools[Tool Registry]
        
        Tools --> Auth[AuthenticateTool<br/>JWT Token Refresh]
        Tools --> Agents[GetAgentsTool<br/>List/Search Agents]
        Tools --> Ports[GetAgentPortsTool<br/>Network Ports Info]
        Tools --> Packages[GetAgentPackagesTool<br/>Installed Packages]
        Tools --> Processes[GetAgentProcessesTool<br/>Running Processes]
        Tools --> Rules[ListRulesTool<br/>Detection Rules]
        Tools --> RuleFile[GetRuleFileContentTool<br/>Rule XML Content]
        Tools --> RuleFiles[GetRuleFilesTool<br/>List Rule Files]
        Tools --> SCA[GetAgentSCATool<br/>Security Compliance]
        Tools --> SCAChecks[GetSCAPolicyChecksTool<br/>Detailed Checks]
    end
    
    subgraph "Wazuh Client"
        HTTPClient[Async HTTP Client<br/>httpx with HTTP/2]
        TokenMgr[JWT Token Manager<br/>Auto-refresh]
        
        HTTPClient --> TokenMgr
    end
    
    subgraph "Wazuh Manager API"
        API[REST API Endpoints<br/>Port 55000]
        
        API --> AgentsAPI[/agents]
        API --> SysAPI[/syscollector]
        API --> RulesAPI[/rules]
        API --> SCAAPI[/sca]
    end
    
    Auth --> HTTPClient
    Agents --> HTTPClient
    Ports --> HTTPClient
    Packages --> HTTPClient
    Processes --> HTTPClient
    Rules --> HTTPClient
    RuleFile --> HTTPClient
    RuleFiles --> HTTPClient
    SCA --> HTTPClient
    SCAChecks --> HTTPClient
    
    HTTPClient --> API
    
    style FastMCP fill:#e1f0ff
    style HTTPClient fill:#ffe1f0
    style API fill:#f0ffe1
```

## 6. Elasticsearch Query Construction

```mermaid
flowchart LR
    Input[Query Parameters<br/>time_range, action_type,<br/>IPs, users, severity]
    
    Input --> TimeCalc[Calculate Time Range]
    TimeCalc --> StartTime[start_time]
    TimeCalc --> EndTime[end_time]
    
    Input --> IntentCheck{Query Type?}
    
    IntentCheck -->|Authentication| AuthBuilder[Auth Query Builder]
    IntentCheck -->|Alerts| AlertBuilder[Alert Query Builder]
    
    AuthBuilder --> BaseDSL[Base DSL Structure<br/>bool query with filters]
    AlertBuilder --> BaseDSL
    
    BaseDSL --> TimeFilter[Add Time Range Filter<br/>@timestamp range]
    
    TimeFilter --> ShouldClauses[Add Should Clauses<br/>rule.groups, rule.description,<br/>event.category]
    
    ShouldClauses --> ActionFilter{Action Type?}
    
    ActionFilter -->|failed| FailedFilter[Add Failed Filters<br/>rule.level >= 5,<br/>status=failed]
    ActionFilter -->|successful| SuccessFilter[Add Success Filters<br/>rule.level <= 4,<br/>status=success]
    ActionFilter -->|all| NoFilter[No additional filters]
    
    FailedFilter --> EntityFilter
    SuccessFilter --> EntityFilter
    NoFilter --> EntityFilter
    
    EntityFilter{Has Entities?}
    
    EntityFilter -->|IPs| AddIPFilter[Add IP Filter<br/>data.srcip terms]
    EntityFilter -->|Users| AddUserFilter[Add User Filter<br/>data.srcuser terms]
    EntityFilter -->|None| SkipEntity[Skip entity filters]
    
    AddIPFilter --> SortConfig
    AddUserFilter --> SortConfig
    SkipEntity --> SortConfig
    
    SortConfig[Configure Sort<br/>@timestamp desc,<br/>rule.level desc]
    
    SortConfig --> FinalDSL[Final Elasticsearch DSL Query]
    
    FinalDSL --> Execute[Execute Search<br/>indices: wazuh-alerts-*,<br/>wazuh-archives-*, filebeat-*]
    
    Execute --> Results[Return Hits]
    
    style Input fill:#e6f3ff
    style FinalDSL fill:#ffe6f0
    style Execute fill:#e6ffe6
    style Results fill:#fff4e6
```

## 7. AI Intelligence Flow

```mermaid
graph TB
    subgraph "AI Query Analysis Phase"
        UserQuery[User Query Text]
        
        UserQuery --> Prompt1[Generate Analysis Prompt<br/>Security expert context<br/>JSON schema specification]
        
        Prompt1 --> GroqCall1[Groq LLM API Call<br/>ainvoke method]
        
        GroqCall1 --> Parse1[Parse Response<br/>Extract JSON]
        
        Parse1 --> Validate1{Valid JSON?}
        
        Validate1 -->|Yes| StructuredAnalysis[Structured Analysis Object<br/>intent, entities, approach,<br/>confidence, reasoning]
        Validate1 -->|No| KeywordAnalysis[Fallback Keyword Analysis<br/>Regex patterns, word matching]
        
        KeywordAnalysis --> StructuredAnalysis
    end
    
    subgraph "Data Retrieval Phase"
        StructuredAnalysis --> ExecutionEngine[Execution Engine]
        ExecutionEngine --> RawData[Raw Data Results<br/>Events, agents, metrics]
    end
    
    subgraph "AI Formatting Phase"
        RawData --> Summarize[Summarize Raw Data<br/>Count metrics, extract samples]
        
        Summarize --> Prompt2[Generate Formatting Prompt<br/>Security analyst persona<br/>Professional report structure]
        
        Prompt2 --> GroqCall2[Groq LLM API Call<br/>ainvoke method]
        
        GroqCall2 --> Parse2[Parse Response<br/>Extract insights]
        
        Parse2 --> Validate2{AI Success?}
        
        Validate2 -->|Yes| IntelligentReport[🧠 Intelligent Security Report<br/>Executive summary<br/>Risk assessment<br/>Recommendations<br/>Technical details]
        
        Validate2 -->|No| FallbackReport[📋 Structured Fallback Report<br/>Findings table<br/>Basic analysis<br/>Generic recommendations]
        
        IntelligentReport --> FinalOutput[Final User Output]
        FallbackReport --> FinalOutput
    end
    
    style UserQuery fill:#e1f5ff
    style GroqCall1 fill:#ffe1e1
    style GroqCall2 fill:#ffe1e1
    style IntelligentReport fill:#e1ffe1
    style FinalOutput fill:#fff4e1
```

## 8. Error Handling & Fallback Strategy

```mermaid
flowchart TD
    Start[System Start] --> CheckES{Elasticsearch<br/>Available?}
    
    CheckES -->|Yes| ESReady[✅ ES Ready]
    CheckES -->|No| ESWarn[⚠️ ES Unavailable<br/>Set es = None]
    
    ESReady --> CheckLLM{Groq LLM<br/>Configured?}
    ESWarn --> CheckLLM
    
    CheckLLM -->|Yes| LLMReady[✅ LLM Ready]
    CheckLLM -->|No| LLMWarn[⚠️ LLM Unavailable<br/>Set decision_llm = None]
    
    LLMReady --> QueryPhase[Query Processing Phase]
    LLMWarn --> QueryPhase
    
    QueryPhase --> TryAI{AI Analysis<br/>Available?}
    
    TryAI -->|Yes| AIAnalysis[AI Query Analysis]
    TryAI -->|No| KeywordAnalysis[Keyword Fallback]
    
    AIAnalysis --> AISuccess{AI Parse<br/>Success?}
    
    AISuccess -->|Yes| ExecutePlan[Execute Query Plan]
    AISuccess -->|No| KeywordAnalysis
    
    KeywordAnalysis --> ExecutePlan
    
    ExecutePlan --> ESQuery{ES Query<br/>Needed?}
    
    ESQuery -->|Yes| ESAvailable{ES<br/>Available?}
    ESQuery -->|No| MCPOnly[MCP Server Only]
    
    ESAvailable -->|Yes| QueryES[Query Elasticsearch]
    ESAvailable -->|No| MockData[Return Mock Data<br/>+ Error Message]
    
    QueryES --> ESError{ES Error?}
    
    ESError -->|Yes| LogError[Log Error<br/>Continue with partial data]
    ESError -->|No| ESResults[ES Results]
    
    LogError --> Aggregate[Aggregate Results]
    ESResults --> Aggregate
    MockData --> Aggregate
    MCPOnly --> Aggregate
    
    Aggregate --> TryFormat{AI Formatting<br/>Available?}
    
    TryFormat -->|Yes| AIFormat[AI Response Formatting]
    TryFormat -->|No| BasicFormat[Basic Structured Format]
    
    AIFormat --> FormatSuccess{Format<br/>Success?}
    
    FormatSuccess -->|Yes| FinalReport[Final Report]
    FormatSuccess -->|No| BasicFormat
    
    BasicFormat --> FinalReport
    
    FinalReport --> UserOutput[📊 Display to User]
    
    style ESReady fill:#90EE90
    style LLMReady fill:#90EE90
    style ESWarn fill:#FFD700
    style LLMWarn fill:#FFD700
    style MockData fill:#FFB6C1
    style LogError fill:#FFB6C1
```

## 9. Authentication & Token Management (MCP Server)

```mermaid
sequenceDiagram
    participant Client as MCP Client<br/>(Analyzer)
    participant Server as MCP Server
    participant WClient as Wazuh Client
    participant Wazuh as Wazuh Manager

    Note over WClient: Token initially None
    
    Client->>Server: Tool Call Request<br/>(e.g., GetAgentsTool)
    
    Server->>WClient: _get_client()
    
    WClient->>WClient: Check token expiry<br/>_refresh_token()
    
    alt Token Expired or Missing
        WClient->>Wazuh: POST /security/user/authenticate<br/>Basic Auth (username:password)
        Wazuh-->>WClient: {"data": {"token": "eyJ..."}}
        WClient->>WClient: Store token + expiry<br/>(15 minutes)
    end
    
    WClient->>Wazuh: GET /agents<br/>Authorization: Bearer {token}
    
    alt Token Valid
        Wazuh-->>WClient: 200 OK + Agent Data
        WClient-->>Server: Return Data
        Server-->>Client: Tool Response (JSON)
    else Token Expired During Request
        Wazuh-->>WClient: 401 Unauthorized
        WClient->>Wazuh: Re-authenticate<br/>POST /security/user/authenticate
        Wazuh-->>WClient: New Token
        WClient->>Wazuh: Retry GET /agents<br/>New Bearer Token
        Wazuh-->>WClient: 200 OK + Agent Data
        WClient-->>Server: Return Data
        Server-->>Client: Tool Response (JSON)
    end
```

## 10. Complete System Interaction (Real Example)

```mermaid
sequenceDiagram
    participant User as 👤 Security Analyst
    participant CLI as Command Line Interface
    participant Analyzer as Intelligent Analyzer
    participant Groq as 🧠 Groq LLM
    participant ES as 🔍 Elasticsearch
    participant MCP as 🔧 MCP Server
    participant Wazuh as Wazuh Manager

    User->>CLI: "Show me failed login attempts from yesterday"
    CLI->>Analyzer: analyze_query(query)
    
    Note over Analyzer: 🧠 Step 1: AI Analysis
    Analyzer->>Groq: Analyze query intent<br/>(Natural language → Structured)
    Groq-->>Analyzer: {"intent": "authentication",<br/>"action_type": "failed",<br/>"time_range": "yesterday"}
    
    Note over Analyzer: 📋 Step 2: Create Plan
    Analyzer->>Analyzer: _create_execution_plan()<br/>Plan: Query Elasticsearch for auth events
    
    Note over Analyzer: ⚡ Step 3: Execute
    Analyzer->>Analyzer: _execute_elasticsearch_query()
    
    Analyzer->>Analyzer: _build_auth_elasticsearch_query()<br/>Build DSL with:<br/>- Time: yesterday 00:00-23:59<br/>- Type: authentication_failed<br/>- Level: >= 5
    
    Analyzer->>ES: POST /wazuh-alerts-*/_search<br/>DSL Query
    ES-->>Analyzer: 35 hits returned<br/>[{timestamp, src_ip, user, rule}...]
    
    Note over Analyzer: 🎨 Step 4: Format Response
    Analyzer->>Analyzer: _format_detailed_response()<br/>Extract: IPs, users, patterns
    
    Analyzer->>Groq: Generate security analysis for:<br/>- 35 failed attempts<br/>- 20 from IP 192.168.1.99<br/>- Targeting root/admin<br/>- 2-min intervals
    
    Groq-->>Analyzer: "⚠️ BRUTE FORCE DETECTED<br/>High-risk pattern identified.<br/>Recommendations:<br/>1. Block IP immediately<br/>2. Enable fail2ban<br/>3. Review account security"
    
    Analyzer->>CLI: Formatted Report:<br/>================<br/>FINDINGS: 35 events<br/>ANALYSIS: Brute force attack<br/>RECOMMENDATIONS: [...]<br/>DETAILS: [Sample events]
    
    CLI->>User: Display formatted report
```

---

## How to Use These Diagrams

### For Documentation:
1. Copy the code blocks into Markdown files
2. GitHub, GitLab, and many editors render Mermaid automatically
3. Use online tools like [mermaid.live](https://mermaid.live) to preview

### For Presentations:
1. Export as SVG/PNG from mermaid.live
2. Import into PowerPoint/Google Slides
3. Use in technical design documents

### For Code Comments:
- Reference diagram numbers in your code
- Example: `# See Diagram 2 (Query Flow) for sequence`

---

## Diagram Legend

- 🎯 = Main orchestration component
- 🧠 = AI/LLM component  
- 🔍 = Data storage/search
- 🔧 = API/Tool layer
- 👤 = Human user
- 📊 = Output/Report

### Color Coding:
- **Light Blue** = User interface
- **Light Red** = AI/LLM operations
- **Light Yellow** = Processing/orchestration
- **Light Green** = Data retrieval
- **Light Purple** = API/middleware
