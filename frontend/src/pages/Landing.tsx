import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { 
  Terminal, 
  Shield, 
  Brain, 
  Network, 
  CheckCircle2, 
  AlertTriangle,
  Lock,
  Clock,
  Database,
  Zap,
  MessageSquare,
  FileText,
  Activity,
  Users,
  ArrowRight,
  Github,
  Linkedin,
  Twitter
} from "lucide-react";
import { useState, useEffect } from "react";

const Landing = () => {
  const [currentQueryIndex, setCurrentQueryIndex] = useState(0);
  const [isTyping, setIsTyping] = useState(true);

  const demoQueries = [
    { query: "Show me failed login attempts from yesterday", response: "Analyzing authentication events...", result: "Found 35 failed attempts. Brute force pattern detected." },
    { query: "Which agents have suspicious port activity?", response: "Scanning network connections...", result: "3 agents detected with unusual outbound traffic." },
    { query: "List all critical alerts from the last hour", response: "Retrieving security alerts...", result: "8 critical threats identified. Immediate action required." },
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setIsTyping(false);
      setTimeout(() => {
        setCurrentQueryIndex((prev) => (prev + 1) % demoQueries.length);
        setIsTyping(true);
      }, 2000);
    }, 6000);

    return () => clearInterval(timer);
  }, []);

  const currentQuery = demoQueries[currentQueryIndex];

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Navigation Header */}
      <header className="fixed top-0 left-0 right-0 z-50 border-b border-border bg-background/80 backdrop-blur-lg">
        <div className="container mx-auto flex h-16 items-center justify-between px-6">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="text-xl font-bold">SecureSight AI</span>
            <span className="h-2 w-2 rounded-full bg-primary"></span>
          </div>
          
          <nav className="hidden md:flex items-center gap-8">
            <a href="#features" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">Features</a>
            <a href="#architecture" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">Architecture</a>
            <a href="#use-cases" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">Use Cases</a>
            <a href="#tech" className="text-sm text-foreground-secondary hover:text-foreground transition-colors">Documentation</a>
          </nav>

          <Link to="/chat">
            <Button variant="default" size="lg">
              Launch Platform
            </Button>
          </Link>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 px-6 min-h-screen flex items-center justify-center grid-pattern">
        <div className="container mx-auto max-w-6xl text-center">
          <h1 className="text-6xl font-bold mb-6 leading-tight">
            AI-Powered Security Intelligence<br />
            for Modern Threat Analysis
          </h1>
          
          <p className="text-xl text-foreground-secondary max-w-2xl mx-auto mb-12 leading-relaxed">
            Transform complex security investigations into natural conversations. 
            Query Wazuh SIEM and Elasticsearch using plain English. 
            Get actionable intelligence in seconds, not hours.
          </p>

          {/* Simulated Terminal */}
          <div className="max-w-3xl mx-auto mb-12 rounded-lg border border-card-border bg-card overflow-hidden shadow-lg glow-red-hover">
            <div className="flex items-center gap-2 px-4 py-3 bg-background-secondary border-b border-card-border">
              <div className="flex gap-1.5">
                <div className="h-3 w-3 rounded-full bg-error"></div>
                <div className="h-3 w-3 rounded-full bg-warning"></div>
                <div className="h-3 w-3 rounded-full bg-success"></div>
              </div>
              <span className="text-xs text-foreground-muted ml-2">SecureSight Terminal</span>
            </div>
            <div className="p-6 text-left font-mono text-sm space-y-3">
              <div className="flex gap-2">
                <span className="text-primary">{'>'}</span>
                <span className={isTyping ? "typewriter" : ""}>{currentQuery.query}</span>
              </div>
              <div className="text-warning">{currentQuery.response}</div>
              <div className="text-success">{currentQuery.result}</div>
            </div>
          </div>

          {/* CTAs */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-8">
            <Link to="/chat">
              <Button variant="default" size="lg" className="gap-2">
                Start Analyzing Now <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
          </div>

          {/* Tech Badges */}
          <div className="flex flex-wrap items-center justify-center gap-3 text-xs text-foreground-muted">
            <span className="px-3 py-1 rounded-full bg-secondary">Groq LLM</span>
            <span className="px-3 py-1 rounded-full bg-secondary">Elasticsearch</span>
            <span className="px-3 py-1 rounded-full bg-secondary">Wazuh MCP</span>
            <span className="px-3 py-1 rounded-full bg-secondary">Real-time Analysis</span>
          </div>
        </div>
      </section>

      {/* Problem Statement */}
      <section className="py-20 px-6 bg-background-secondary">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-4xl font-semibold text-center mb-16">Challenges in Security Operations</h2>
          
          <div className="grid md:grid-cols-3 gap-8">
            <div className="p-6 rounded-lg border border-card-border bg-card hover:border-primary transition-all duration-200 glow-red-hover">
              <Terminal className="h-12 w-12 text-primary mb-4" />
              <h3 className="text-xl font-semibold mb-3">Complex Query Languages</h3>
              <p className="text-foreground-secondary">
                Security analysts spend hours writing Elasticsearch DSL queries and navigating complex APIs instead of investigating threats.
              </p>
            </div>

            <div className="p-6 rounded-lg border border-card-border bg-card hover:border-primary transition-all duration-200 glow-red-hover">
              <Database className="h-12 w-12 text-primary mb-4" />
              <h3 className="text-xl font-semibold mb-3">Siloed Information Sources</h3>
              <p className="text-foreground-secondary">
                Critical security data scattered across Wazuh Manager, Elasticsearch indices, and multiple dashboards requiring constant context switching.
              </p>
            </div>

            <div className="p-6 rounded-lg border border-card-border bg-card hover:border-primary transition-all duration-200 glow-red-hover">
              <Clock className="h-12 w-12 text-primary mb-4" />
              <h3 className="text-xl font-semibold mb-3">Slow Incident Response</h3>
              <p className="text-foreground-secondary">
                Time lost translating security questions into technical queries delays threat detection and incident mitigation.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Solution Overview */}
      <section className="py-20 px-6">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-4xl font-semibold text-center mb-4">Your AI Security Analyst</h2>
          <p className="text-xl text-foreground-secondary text-center mb-16">Natural language interface powered by advanced AI</p>
          
          <div className="grid md:grid-cols-2 gap-8 items-center">
            <div className="space-y-4">
              <span className="text-sm text-foreground-muted">Traditional Approach</span>
              <div className="p-6 rounded-lg bg-background-secondary border border-card-border font-mono text-sm overflow-x-auto">
                <pre className="text-foreground-secondary">{`{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {...}}},
        {"match": {"rule.groups": "authentication"}},
        {"match": {"data.srcip": "192.168.1.99"}}
      ]
    }
  },
  "size": 100,
  "sort": [{"@timestamp": "desc"}]
}`}</pre>
              </div>
              <span className="text-xs text-warning">Complex, time-consuming</span>
            </div>

            <div className="space-y-4">
              <span className="text-sm text-foreground-muted">AI Approach</span>
              <div className="p-6 rounded-lg bg-card border border-primary shadow-lg">
                <p className="text-lg">Show me failed login attempts from 192.168.1.99 yesterday</p>
              </div>
              <span className="text-xs text-success">Simple, instant</span>
            </div>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" className="py-20 px-6 bg-background-secondary">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-4xl font-semibold text-center mb-16">Enterprise Capabilities</h2>
          
          <div className="grid md:grid-cols-3 gap-6">
            <div className="p-6 rounded-lg border border-card-border bg-card">
              <MessageSquare className="h-8 w-8 text-primary mb-3" />
              <h3 className="text-lg font-semibold mb-2">Natural Language Processing</h3>
              <p className="text-sm text-foreground-secondary">Ask security questions in plain English without learning query syntax</p>
            </div>

            <div className="p-6 rounded-lg border border-card-border bg-card">
              <Zap className="h-8 w-8 text-primary mb-3" />
              <h3 className="text-lg font-semibold mb-2">Real-Time Intelligence</h3>
              <p className="text-sm text-foreground-secondary">Get instant answers from live Wazuh and Elasticsearch data streams</p>
            </div>

            <div className="p-6 rounded-lg border border-card-border bg-card">
              <Brain className="h-8 w-8 text-primary mb-3" />
              <h3 className="text-lg font-semibold mb-2">AI-Powered Analysis</h3>
              <p className="text-sm text-foreground-secondary">Receive contextual insights, threat assessments, and remediation recommendations</p>
            </div>

            <div className="p-6 rounded-lg border border-card-border bg-card">
              <Network className="h-8 w-8 text-primary mb-3" />
              <h3 className="text-lg font-semibold mb-2">Multi-Source Correlation</h3>
              <p className="text-sm text-foreground-secondary">Unified view combining Wazuh alerts, agent data, and Elasticsearch logs</p>
            </div>

            <div className="p-6 rounded-lg border border-card-border bg-card">
              <Shield className="h-8 w-8 text-primary mb-3" />
              <h3 className="text-lg font-semibold mb-2">Autonomous Monitoring</h3>
              <p className="text-sm text-foreground-secondary">Auto-detection mode for proactive threat identification and alerting</p>
            </div>

            <div className="p-6 rounded-lg border border-card-border bg-card">
              <CheckCircle2 className="h-8 w-8 text-primary mb-3" />
              <h3 className="text-lg font-semibold mb-2">Actionable Recommendations</h3>
              <p className="text-sm text-foreground-secondary">Security best practices and immediate response actions for detected threats</p>
            </div>
          </div>
        </div>
      </section>

      {/* Use Cases */}
      <section id="use-cases" className="py-20 px-6">
        <div className="container mx-auto max-w-6xl">
          <h2 className="text-4xl font-semibold text-center mb-16">Built for Security Professionals</h2>
          
          <div className="grid md:grid-cols-2 gap-6">
            <div className="p-8 rounded-lg border border-card-border bg-card">
              <AlertTriangle className="h-10 w-10 text-primary mb-4" />
              <h3 className="text-xl font-semibold mb-2">Incident Response</h3>
              <p className="text-sm text-foreground-muted mb-4">Investigate Security Incidents</p>
              <p className="text-sm text-foreground-secondary mb-3">Example: "Show high-severity alerts from the last hour"</p>
              <p className="text-sm text-success">→ Rapid triage and threat containment</p>
            </div>

            <div className="p-8 rounded-lg border border-card-border bg-card">
              <Activity className="h-10 w-10 text-primary mb-4" />
              <h3 className="text-xl font-semibold mb-2">Threat Hunting</h3>
              <p className="text-sm text-foreground-muted mb-4">Proactive Threat Detection</p>
              <p className="text-sm text-foreground-secondary mb-3">Example: "Find unusual authentication patterns for admin accounts"</p>
              <p className="text-sm text-success">→ Early identification of advanced persistent threats</p>
            </div>

            <div className="p-8 rounded-lg border border-card-border bg-card">
              <FileText className="h-10 w-10 text-primary mb-4" />
              <h3 className="text-xl font-semibold mb-2">Compliance Auditing</h3>
              <p className="text-sm text-foreground-muted mb-4">Regulatory Compliance</p>
              <p className="text-sm text-foreground-secondary mb-3">Example: "List all failed login attempts this month"</p>
              <p className="text-sm text-success">→ Automated audit trail generation</p>
            </div>

            <div className="p-8 rounded-lg border border-card-border bg-card">
              <Users className="h-10 w-10 text-primary mb-4" />
              <h3 className="text-xl font-semibold mb-2">Agent Management</h3>
              <p className="text-sm text-foreground-muted mb-4">Infrastructure Monitoring</p>
              <p className="text-sm text-foreground-secondary mb-3">Example: "Which agents are offline or have suspicious processes?"</p>
              <p className="text-sm text-success">→ Proactive system health management</p>
            </div>
          </div>
        </div>
      </section>

      {/* Tech Stack */}
      <section id="tech" className="py-20 px-6 bg-background-secondary">
        <div className="container mx-auto max-w-6xl text-center">
          <h2 className="text-3xl font-semibold mb-12">Enterprise-Grade Technology Stack</h2>
          
          <div className="flex flex-wrap justify-center gap-4 mb-12">
            <span className="px-4 py-2 rounded-full bg-card border border-card-border">Groq LLM (llama-3.3-70b)</span>
            <span className="px-4 py-2 rounded-full bg-card border border-card-border">Elasticsearch Integration</span>
            <span className="px-4 py-2 rounded-full bg-card border border-card-border">Wazuh Manager API</span>
            <span className="px-4 py-2 rounded-full bg-card border border-card-border">MCP Protocol</span>
            <span className="px-4 py-2 rounded-full bg-card border border-card-border">JWT Authentication</span>
            <span className="px-4 py-2 rounded-full bg-card border border-card-border">Async Python</span>
            <span className="px-4 py-2 rounded-full bg-card border border-card-border">REST API</span>
            <span className="px-4 py-2 rounded-full bg-card border border-card-border">Real-Time Processing</span>
          </div>

          <div className="flex flex-wrap justify-center gap-6 text-sm text-foreground-muted">
            <span className="flex items-center gap-2"><Lock className="h-4 w-4" /> Enterprise encryption</span>
            <span className="flex items-center gap-2"><Shield className="h-4 w-4" /> Role-based access control</span>
            <span className="flex items-center gap-2"><FileText className="h-4 w-4" /> Audit logging</span>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-6 bg-gradient-to-r from-primary/10 to-error/10">
        <div className="container mx-auto max-w-4xl text-center">
          <h2 className="text-4xl font-bold mb-4">Transform Your Security Operations</h2>
          <p className="text-xl text-foreground-secondary mb-10">Join security teams already using AI-powered intelligence</p>
          
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-8">
            <Link to="/chat">
              <Button variant="default" size="lg">Launch Platform Now</Button>
            </Link>
          </div>

          <div className="flex flex-wrap justify-center gap-6 text-sm text-foreground-secondary">
            <span className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-success" /> No credit card required</span>
            <span className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-success" /> Enterprise support available</span>
            <span className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-success" /> SOC integration ready</span>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-6 bg-background-secondary border-t border-border">
        <div className="container mx-auto max-w-6xl">
          <div className="grid md:grid-cols-4 gap-8 mb-8">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-5 w-5 text-primary" />
                <span className="font-bold">SecureSight AI</span>
              </div>
              <p className="text-sm text-foreground-muted">AI-powered security intelligence</p>
            </div>

            <div>
              <h4 className="font-semibold mb-3">Product</h4>
              <ul className="space-y-2 text-sm text-foreground-secondary">
                <li><a href="#features" className="hover:text-foreground">Features</a></li>
                <li><a href="#" className="hover:text-foreground">Documentation</a></li>
                <li><a href="#" className="hover:text-foreground">API Reference</a></li>
                <li><a href="#" className="hover:text-foreground">Pricing</a></li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold mb-3">Resources</h4>
              <ul className="space-y-2 text-sm text-foreground-secondary">
                <li><a href="#" className="hover:text-foreground">Blog</a></li>
                <li><a href="#" className="hover:text-foreground">Case Studies</a></li>
                <li><a href="#" className="hover:text-foreground">Security Best Practices</a></li>
                <li><a href="#" className="hover:text-foreground">Community Forum</a></li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold mb-3">Company</h4>
              <ul className="space-y-2 text-sm text-foreground-secondary">
                <li><a href="#" className="hover:text-foreground">About Us</a></li>
                <li><a href="#" className="hover:text-foreground">Contact</a></li>
                <li><a href="#" className="hover:text-foreground">Privacy Policy</a></li>
                <li><a href="#" className="hover:text-foreground">Terms of Service</a></li>
              </ul>
            </div>
          </div>

          <div className="pt-8 border-t border-border flex flex-col sm:flex-row items-center justify-between gap-4">
            <p className="text-sm text-foreground-muted">© 2025 SecureSight AI. All rights reserved.</p>
            <div className="flex items-center gap-4">
              <a href="#" className="text-foreground-secondary hover:text-foreground"><Github className="h-5 w-5" /></a>
              <a href="#" className="text-foreground-secondary hover:text-foreground"><Linkedin className="h-5 w-5" /></a>
              <a href="#" className="text-foreground-secondary hover:text-foreground"><Twitter className="h-5 w-5" /></a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
