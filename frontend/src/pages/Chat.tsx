import { useState, useRef, useEffect } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Shield, Send, User, Sparkles, AlertTriangle, Info, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { io, Socket } from "socket.io-client";

const BACKEND_URL = "http://localhost:5000";

interface Message {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: Date;
}

interface ThreatAlert {
  id: string;
  scanNumber: number;
  timestamp: string;
  severity: string;
  totalEvents: number;
  findings: any[];
  summary: string;
}

const Chat = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [autoMode, setAutoMode] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [isInitialMount, setIsInitialMount] = useState(true);
  const [threats, setThreats] = useState<ThreatAlert[]>([]);
  const [selectedThreat, setSelectedThreat] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const socketRef = useRef<Socket | null>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Initialize WebSocket connection
  useEffect(() => {
    console.log("[SOCKET] Initializing WebSocket connection...");
    
    const socket = io(BACKEND_URL, {
      transports: ["websocket", "polling"],
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    socketRef.current = socket;

    socket.on("connect", () => {
      console.log("[SOCKET] Connected successfully! Socket ID:", socket.id);
      setIsConnected(true);
      setIsInitialMount(false);
      toast.success("Connected to Security Analyzer");
    });

    socket.on("disconnect", () => {
      console.log("[SOCKET] Disconnected from server");
      setIsConnected(false);
      toast.error("Disconnected from server");
    });

    socket.on("connection_response", (data) => {
      console.log("[SOCKET] Connection response:", data);
    });

    socket.on("chat_processing", (data) => {
      console.log("[SOCKET] Processing query:", data);
      setIsLoading(true);
    });

    socket.on("chat_response", (data) => {
      console.log("[SOCKET] Received chat response:", data);
      setIsLoading(false);
      
      const aiMessage: Message = {
        id: Date.now().toString(),
        role: "assistant",
        content: data.response,
        timestamp: new Date(data.timestamp),
      };
      
      setMessages((prev) => [...prev, aiMessage]);
    });

    socket.on("chat_error", (data) => {
      console.error("[SOCKET] Chat error:", data);
      setIsLoading(false);
      toast.error(`Error: ${data.error}`);
    });

    socket.on("auto_mode_started", (data) => {
      console.log("[SOCKET] Auto mode started:", data);
      
      const systemMsg: Message = {
        id: Date.now().toString(),
        role: "system",
        content: `🔄 ${data.message}`,
        timestamp: new Date(data.timestamp),
      };
      
      setMessages((prev) => [...prev, systemMsg]);
      toast.success("Auto monitoring activated", {
        description: "Scanning every 10 seconds for security threats",
        duration: 5000,
      });
    });

    socket.on("auto_mode_stopped", (data) => {
      console.log("[SOCKET] Auto mode stopped:", data);
      
      const systemMsg: Message = {
        id: Date.now().toString(),
        role: "system",
        content: `🛑 ${data.message}`,
        timestamp: new Date(data.timestamp),
      };
      
      setMessages((prev) => [...prev, systemMsg]);
      toast.info("Auto monitoring deactivated", {
        description: "Switched back to normal chat mode",
        duration: 3000,
      });
    });

    socket.on("scan_start", (data) => {
      console.log("[SOCKET] Scan started:", data);
    });

    socket.on("scan_clear", (data) => {
      console.log("[SOCKET] Scan clear:", data);
      
      const systemMsg: Message = {
        id: Date.now().toString(),
        role: "system",
        content: `✅ ${data.message}`,
        timestamp: new Date(data.timestamp),
      };
      
      setMessages((prev) => [...prev, systemMsg]);
    });

    socket.on("security_alert", (data) => {
      console.log("[SOCKET] 🚨 SECURITY ALERT:", data);
      
      const alertMsg: Message = {
        id: Date.now().toString(),
        role: "assistant",
        content: data.alert,
        timestamp: new Date(data.timestamp),
      };
      
      setMessages((prev) => [...prev, alertMsg]);
      
      // Add to threats sidebar
      const threat: ThreatAlert = {
        id: Date.now().toString(),
        scanNumber: data.scan_number,
        timestamp: data.timestamp,
        severity: data.severity || "high",
        totalEvents: data.findings?.total_suspicious || 0,
        findings: data.findings?.findings || [],
        summary: data.alert.substring(0, 200) + "...",
      };
      
      setThreats((prev) => [threat, ...prev]);
      
      toast.error("Security Alert Detected!", {
        description: `Scan #${data.scan_number} found suspicious activity`,
        duration: 10000,
        action: {
          label: "View Details",
          onClick: () => setSelectedThreat(threat.id),
        },
      });
    });

    socket.on("scan_error", (data) => {
      console.error("[SOCKET] Scan error:", data);
      toast.error(`Scan error: ${data.error}`);
    });

    // Telegram message events (for conversation mode via Telegram only)
    socket.on("telegram_message", (data) => {
      console.log("[SOCKET] Telegram message received:", data);
      
      const telegramMsg: Message = {
        id: Date.now().toString(),
        role: "user",
        content: `📱 ${data.username}: ${data.message}`,
        timestamp: new Date(data.timestamp),
      };
      
      setMessages((prev) => [...prev, telegramMsg]);
    });

    socket.on("telegram_response", (data) => {
      console.log("[SOCKET] Telegram response sent:", data);
      
      const responseMsg: Message = {
        id: Date.now().toString(),
        role: "assistant",
        content: data.response,
        timestamp: new Date(data.timestamp),
      };
      
      setMessages((prev) => [...prev, responseMsg]);
      
      toast.success(`Response sent to @${data.username} on Telegram`);
    });

    socket.on("telegram_notification", (data) => {
      console.log("[SOCKET] Telegram notification:", data);
      toast.info("Telegram Bot Available", {
        description: data.message,
        duration: 10000,
      });
    });

    return () => {
      console.log("[SOCKET] Cleaning up WebSocket connection");
      socket.disconnect();
    };
  }, []);

  // Handle auto mode changes
  const previousAutoModeRef = useRef<boolean>(autoMode);
  
  useEffect(() => {
    if (!socketRef.current) return;

    // Skip the initial render
    if (previousAutoModeRef.current === autoMode) {
      previousAutoModeRef.current = autoMode;
      return;
    }

    console.log("[AUTO MODE] Toggle changed:", autoMode);
    previousAutoModeRef.current = autoMode;

    if (autoMode) {
      console.log("[AUTO MODE] Emitting start_auto_mode event");
      socketRef.current.emit("start_auto_mode", { enabled: true });
    } else {
      console.log("[AUTO MODE] Emitting stop_auto_mode event");
      socketRef.current.emit("stop_auto_mode", { enabled: false });
    }
  }, [autoMode]);

  const handleQuickAction = (title: string) => {
    const query = `Analyze: ${title}`;
    setInput(query);
  };

  const quickStartExamples = [
    "Show me high-severity alerts from today",
    "List all offline agents",
    "Analyze authentication failures for 192.168.1.99",
    "Which agents have unusual port activity?",
  ];

  const handleSend = async () => {
    if (!input.trim()) return;
    if (!socketRef.current?.connected) {
      toast.error("Not connected to server");
      return;
    }

    const userMessage: Message = {
      id: Date.now().toString(),
      role: "user",
      content: input,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    const query = input;
    setInput("");
    setIsLoading(true);

    console.log("[CHAT] Sending message via WebSocket:", query);

    try {
      // Send via WebSocket
      socketRef.current.emit("chat_message", {
        message: query,
        timestamp: new Date().toISOString(),
      });

      console.log("[CHAT] Message sent successfully");
    } catch (error) {
      console.error("[CHAT] Error sending message:", error);
      setIsLoading(false);
      toast.error("Failed to send message");
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="flex h-screen bg-background">
      {/* Threats Sidebar */}
      {autoMode && (
        <aside className="w-80 border-r border-border bg-card/50 flex flex-col overflow-hidden">
          <div className="p-4 border-b border-border">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-lg font-bold text-primary">Threats Discovered</h2>
              {threats.length > 0 && (
                <span className="px-2 py-1 bg-error/20 text-error text-xs font-semibold rounded-full">
                  {threats.length}
                </span>
              )}
            </div>
            <p className="text-xs text-foreground-muted">
              Real-time security threats detected by auto monitoring
            </p>
          </div>
          
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {threats.length === 0 ? (
              <div className="text-center py-8">
                <Shield className="h-12 w-12 mx-auto mb-3 text-success opacity-50" />
                <p className="text-sm text-foreground-muted">
                  No threats detected yet
                </p>
                <p className="text-xs text-foreground-muted mt-1">
                  Monitoring active...
                </p>
              </div>
            ) : (
              threats.map((threat) => (
                <div
                  key={threat.id}
                  onClick={() => setSelectedThreat(selectedThreat === threat.id ? null : threat.id)}
                  className={cn(
                    "p-3 rounded-lg border cursor-pointer transition-all",
                    selectedThreat === threat.id
                      ? "border-primary bg-primary/10"
                      : "border-card-border bg-card hover:border-primary/50"
                  )}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className={cn(
                        "h-3.5 w-3.5",
                        threat.severity === "critical" && "text-error",
                        threat.severity === "high" && "text-warning",
                        threat.severity === "medium" && "text-primary"
                      )} />
                      <span className="text-[11px] font-bold text-foreground">
                        Scan #{threat.scanNumber}
                      </span>
                    </div>
                    <span className={cn(
                      "text-[9px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wide",
                      threat.severity === "critical" && "bg-error/20 text-error",
                      threat.severity === "high" && "bg-warning/20 text-warning",
                      threat.severity === "medium" && "bg-primary/20 text-primary"
                    )}>
                      {threat.severity}
                    </span>
                  </div>
                  
                  <div className="text-[10px] text-foreground-muted mb-2 font-medium">
                    🕒 {new Date(threat.timestamp).toLocaleString('en-US', {
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit'
                    })}
                  </div>
                  
                  <div className="flex items-center gap-2 mb-1">
                    <div className="text-[10px] text-foreground-secondary">
                      <strong className="text-error font-bold text-sm">{threat.totalEvents}</strong> <span className="text-foreground-muted">events</span>
                    </div>
                    <div className="text-[10px] text-foreground-secondary">
                      • <strong className="font-semibold">{threat.findings.length}</strong> <span className="text-foreground-muted">findings</span>
                    </div>
                  </div>
                  
                  {selectedThreat === threat.id && (
                    <div className="mt-3 pt-3 border-t border-border space-y-2">
                      <p className="text-[10px] font-bold text-foreground mb-2 uppercase tracking-wide">Detailed Findings</p>
                      {threat.findings.length > 0 ? (
                        <div className="space-y-1.5">
                          {threat.findings.map((finding: any, idx: number) => (
                            <div key={idx} className="bg-secondary/30 p-2 rounded border border-card-border">
                              <div className="flex items-start justify-between gap-2 mb-1">
                                <span className="text-[10px] font-semibold text-foreground leading-tight flex-1">
                                  {finding.name || finding.type || "Security Event"}
                                </span>
                                <span className={cn(
                                  "text-[9px] px-1.5 py-0.5 rounded font-bold uppercase",
                                  finding.severity === "critical" && "bg-error/20 text-error",
                                  finding.severity === "high" && "bg-warning/20 text-warning",
                                  finding.severity === "medium" && "bg-primary/20 text-primary",
                                  finding.severity === "low" && "bg-info/20 text-info"
                                )}>
                                  {finding.severity}
                                </span>
                              </div>
                              <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[9px] text-foreground-muted">
                                {finding.count && (
                                  <div>
                                    <span className="font-semibold">Events:</span> <span className="text-error font-bold">{finding.count}</span>
                                  </div>
                                )}
                                {finding.source && (
                                  <div>
                                    <span className="font-semibold">Source:</span> {finding.source}
                                  </div>
                                )}
                                {finding.destination && (
                                  <div className="col-span-2">
                                    <span className="font-semibold">Destination:</span> {finding.destination}
                                  </div>
                                )}
                                {finding.description && (
                                  <div className="col-span-2 mt-1 text-foreground-secondary">
                                    {finding.description}
                                  </div>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-[10px] text-foreground-muted italic">No detailed findings available</p>
                      )}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          // Find the message with the matching scan number
                          const matchingMsg = messages.find(m => 
                            m.role === "assistant" && m.content.includes(`#${threat.scanNumber}`)
                          );
                          if (matchingMsg) {
                            const element = document.getElementById(`msg-${matchingMsg.id}`);
                            if (element) {
                              element.scrollIntoView({ behavior: "smooth", block: "center" });
                              // Add highlight effect
                              element.style.transition = "background-color 0.3s ease";
                              element.style.backgroundColor = "rgba(var(--primary-rgb), 0.1)";
                              setTimeout(() => {
                                element.style.backgroundColor = "";
                              }, 2000);
                            }
                          } else {
                            toast.info("Full analysis message not found in chat");
                          }
                        }}
                        className="w-full mt-2 px-3 py-1.5 bg-primary text-primary-foreground text-[10px] font-semibold rounded hover:bg-primary/90 transition-colors flex items-center justify-center gap-1"
                      >
                        <Info className="h-3 w-3" />
                        View Full Analysis in Chat
                      </button>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
          
          {threats.length > 0 && (
            <div className="p-3 border-t border-border">
              <button
                onClick={() => {
                  setThreats([]);
                  toast.info("Threats list cleared");
                }}
                className="w-full px-3 py-2 bg-secondary text-foreground text-xs rounded hover:bg-secondary/80 transition-colors"
              >
                Clear All Threats
              </button>
            </div>
          )}
        </aside>
      )}
      
      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="h-16 border-b border-border bg-background/80 backdrop-blur-lg z-50">
        <div className="container mx-auto h-full px-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/" className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              <span className="font-bold">SecureSight AI</span>
            </Link>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 text-sm">
              <div className={cn(
                "h-2 w-2 rounded-full",
                isConnected ? "bg-success animate-pulse-glow" : "bg-error"
              )}></div>
              <span className="text-foreground-muted">
                {isConnected ? "Connected" : "Disconnected"}
              </span>
            </div>
            
            <div className="flex items-center gap-2">
              <Button
                variant={autoMode ? "default" : "outline"}
                size="sm"
                onClick={() => {
                  setAutoMode(!autoMode);
                }}
                disabled={!isConnected}
                className="text-xs"
              >
                🔍 Auto Mode
              </Button>
            </div>
          </div>
        </div>
      </header>

        {/* Main Chat Area */}
        <main className="flex-1 overflow-y-auto pb-32">
        <div className="container mx-auto max-w-4xl px-6 py-8">
          {messages.length === 0 ? (
            // Empty State
            <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
              <div className="mb-6 p-4 rounded-full bg-primary/10 border-2 border-primary">
                <Sparkles className="h-12 w-12 text-primary" />
              </div>
              <h2 className="text-3xl font-semibold mb-3">Security Intelligence Assistant</h2>
              <p className="text-lg text-foreground-secondary max-w-2xl mb-8">
                Ask questions about your security environment in natural language.
                I analyze Wazuh alerts, Elasticsearch logs, and agent data to provide
                actionable intelligence.
              </p>

              <div className="mb-8 text-left max-w-xl">
                <p className="font-semibold mb-3">I can help you with:</p>
                <ul className="space-y-2 text-foreground-secondary">
                  <li className="flex items-start gap-2">
                    <ChevronRight className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
                    <span>Authentication analysis and failed login investigations</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <ChevronRight className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
                    <span>Security alert triage and threat assessment</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <ChevronRight className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
                    <span>Agent status monitoring and system information</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <ChevronRight className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
                    <span>Network activity analysis and anomaly detection</span>
                  </li>
                </ul>
              </div>

              <div className="flex flex-wrap gap-2 justify-center">
                {quickStartExamples.map((example, idx) => (
                  <button
                    key={idx}
                    onClick={() => setInput(example)}
                    className="px-4 py-2 rounded-lg bg-secondary hover:bg-primary hover:text-primary-foreground transition-colors text-sm border border-card-border"
                  >
                    {example}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            // Messages
            <div className="space-y-6">
              {messages.map((message) => (
                <div
                  id={`msg-${message.id}`}
                  key={message.id}
                  className={cn(
                    "flex gap-4",
                    message.role === "user" && "justify-end",
                    message.role === "system" && "justify-center"
                  )}
                >
                  {message.role === "assistant" && (
                    <div className="flex-shrink-0">
                      <div className="h-8 w-8 rounded-full bg-primary/10 border border-primary flex items-center justify-center">
                        <Sparkles className="h-4 w-4 text-primary" />
                      </div>
                    </div>
                  )}

                  <div
                    className={cn(
                      "max-w-[85%] rounded-lg p-4",
                      message.role === "user" && "bg-secondary ml-auto",
                      message.role === "assistant" && "bg-card border-l-4 border-primary",
                      message.role === "system" && "bg-transparent text-center text-warning italic"
                    )}
                  >
                    {message.role === "assistant" && (
                      <div className="flex items-center gap-2 mb-3">
                        <AlertTriangle className="h-4 w-4 text-primary" />
                        <span className="text-xs font-semibold text-primary uppercase tracking-wider">
                          Security Analysis
                        </span>
                      </div>
                    )}

                    <div className="prose prose-invert prose-sm max-w-none">
                      {message.content.split('\n').map((line, i) => {
                        const trimmedLine = line.trim();
                        
                        // Skip empty lines after headers
                        if (!trimmedLine && i > 0) {
                          return <div key={i} className="h-2" />;
                        }
                        
                        // Main headers (##)
                        if (trimmedLine.startsWith('## ')) {
                          return (
                            <h2 key={i} className="text-xl font-bold mb-3 mt-6 text-primary border-b border-primary/30 pb-2">
                              {trimmedLine.replace('## ', '').replace(/[🔍⚠️🛡️📊]/g, '').trim()}
                            </h2>
                          );
                        }
                        
                        // Sub headers (###)
                        if (trimmedLine.startsWith('### ')) {
                          return (
                            <h3 key={i} className="text-lg font-semibold mb-2 mt-4 text-foreground">
                              {trimmedLine.replace('### ', '')}
                            </h3>
                          );
                        }
                        
                        // Bold text patterns (**text:** or **text**)
                        if (trimmedLine.includes('**')) {
                          const formatted = trimmedLine.replace(/\*\*(.+?)\*\*/g, '<strong class="text-primary font-semibold">$1</strong>');
                          return <p key={i} className="mb-2" dangerouslySetInnerHTML={{ __html: formatted }} />;
                        }
                        
                        // Bullet points (• or -)
                        if (trimmedLine.startsWith('• ') || trimmedLine.startsWith('- ')) {
                          return (
                            <li key={i} className="ml-6 mb-1 text-foreground-secondary list-disc">
                              {trimmedLine.replace(/^[•\-]\s*/, '')}
                            </li>
                          );
                        }
                        
                        // Numbered lists
                        if (trimmedLine.match(/^\d+\.\s/)) {
                          return (
                            <li key={i} className="ml-6 mb-1 text-foreground-secondary list-decimal">
                              {trimmedLine.replace(/^\d+\.\s*/, '')}
                            </li>
                          );
                        }
                        
                        // Section separators (=== or ---)
                        if (trimmedLine.match(/^[=\-]{3,}$/)) {
                          return <hr key={i} className="my-4 border-border" />;
                        }
                        
                        // Code blocks with backticks
                        if (trimmedLine.startsWith('`') && trimmedLine.endsWith('`')) {
                          return (
                            <code key={i} className="block bg-secondary px-3 py-2 rounded mb-2 text-sm font-mono">
                              {trimmedLine.replace(/`/g, '')}
                            </code>
                          );
                        }
                        
                        // Table rows
                        if (trimmedLine.startsWith('| ')) {
                          return null; // Tables handled separately
                        }
                        
                        // Regular paragraphs
                        return trimmedLine ? (
                          <p key={i} className="mb-2 text-foreground-secondary leading-relaxed">
                            {trimmedLine}
                          </p>
                        ) : null;
                      })}
                    </div>

                    <div className="mt-3 text-xs text-foreground-muted">
                      {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </div>

                  {message.role === "user" && (
                    <div className="flex-shrink-0">
                      <div className="h-8 w-8 rounded-full bg-secondary flex items-center justify-center">
                        <User className="h-4 w-4" />
                      </div>
                    </div>
                  )}
                </div>
              ))}

              {isLoading && (
                <div className="flex gap-4">
                  <div className="flex-shrink-0">
                    <div className="h-8 w-8 rounded-full bg-primary/10 border border-primary flex items-center justify-center">
                      <Sparkles className="h-4 w-4 text-primary animate-pulse" />
                    </div>
                  </div>
                  <div className="bg-card border-l-4 border-primary rounded-lg p-4">
                    <p className="text-foreground-secondary italic">Analyzing query and retrieving data...</p>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>
          )}
        </div>
      </main>

        {/* Input Area */}
        <div className="border-t border-border bg-background">
          <div className="container mx-auto max-w-4xl px-6 py-4">
            <>
              <div className="relative">
                <Textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask about security events, agents, alerts, or compliance..."
                  className="min-h-[56px] max-h-[200px] pr-12 resize-none bg-card border-card-border focus:border-primary"
                  disabled={autoMode}
                />
                <Button
                  onClick={handleSend}
                  disabled={!input.trim() || isLoading || !isConnected || autoMode}
                  size="icon"
                  className="absolute right-2 bottom-2"
                >
                  <Send className="h-4 w-4" />
                </Button>
              </div>
              <div className="mt-2 flex items-center justify-between text-xs text-foreground-muted">
                <span>
                  {autoMode 
                    ? "Auto Mode active - monitoring for threats..." 
                    : "Press Enter to send • Shift+Enter for new line"
                  }
                </span>
                <span>{input.length} / 2000</span>
              </div>
            </>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Chat;
