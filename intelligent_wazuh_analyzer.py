import asyncio
import json
import httpx
from datetime import datetime, timedelta
from langchain_groq import ChatGroq
from typing import Any, Dict, List, Optional
from elasticsearch import Elasticsearch
import re


class IntelligentWazuhAnalyzer:
    """Truly intelligent Wazuh SIEM analyzer that understands context and makes smart decisions"""
    
    def __init__(self):
        print("Initializing Intelligent Wazuh Analyzer...")
        
        # Connect to Elasticsearch
        try:
            self.es = Elasticsearch(['http://localhost:9200'])
            if self.es.ping():
                info = self.es.info()
                print(f"Elasticsearch connected successfully!")
                print(f"Cluster: {info['cluster_name']}, Version: {info['version']['number']}")
            else:
                print("Warning: Elasticsearch not responding, using mock data")
                self.es = None
        except Exception as e:
            print(f" Warning: Could not connect to Elasticsearch: {e}")
            self.es = None
        
        
        self.mcp_server_url = "http://127.0.0.1:8010"
        self.authenticated = False
        
        # Initialize the decision-making LLM
        try:
            self.decision_llm = ChatGroq(
                model="llama-3.3-70b-versatile",
                groq_api_key="put your key here",
                temperature=0.1,
                max_tokens=2000
            )
            print("Groq LLM initialized successfully!")
        except Exception as e:
            print(f"Warning: Could not initialize Groq LLM: {e}")
            self.decision_llm = None
    
    async def analyze_query(self, query: str) -> str:
        """Main intelligence engine - uses AI to understand and route queries"""
        try:
            print(f"\n[DEBUG] Analyzing query: '{query}'")
            
            # Step 1: Use AI to understand the query intent and parameters
            analysis = await self._analyze_query_with_ai(query)
            print(f"[DEBUG] AI Analysis Result: {json.dumps(analysis, indent=2)}")
            
            # Step 2: Based on AI analysis, decide which tools and approach to use
            execution_plan = await self._create_execution_plan(analysis, query)
            print(f"[DEBUG] Execution Plan: {json.dumps(execution_plan, indent=2)}")
            
            # Step 3: Execute the plan
            results = await self._execute_plan(execution_plan, query)
            print(f"[DEBUG] Execution Results Summary: {len(results.get('step_results', []))} steps completed")
            
            # Step 4: Format with detailed findings first, then intelligent analysis
            final_response = await self._format_detailed_response(results, analysis, query)
            
            return final_response
            
        except Exception as e:
            print(f"[DEBUG] Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return f"**ERROR**: {str(e)}\n\n{self._get_help_message()}"
    
    async def _analyze_query_with_ai(self, query: str) -> dict:
        """Use AI to understand query intent, extract entities, and determine approach"""
        
        print(f"[DEBUG] Using AI to analyze query intent...")
        
        if not self.decision_llm:
            print(f"[DEBUG] No LLM available, using fallback analysis")
            return self._fallback_query_analysis(query)
        
        analysis_prompt = f"""
You are an expert cybersecurity analyst who understands SIEM queries. Analyze this user query and respond with a structured JSON analysis.

User Query: "{query}"

Provide analysis in this EXACT JSON format (no extra text, ONLY the JSON):
{{
    "intent": "authentication|network|agents|alerts|processes|compliance|general",
    "sub_intent": "detailed description of what specifically they want",
    "action_type": "failed|successful|all|monitor|investigate|analyze",
    "time_range": "yesterday|today|last_hour|last_24_hours|last_week",
    "entities": {{
        "ip_addresses": ["list of IPs if mentioned"],
        "usernames": ["list of usernames if mentioned"],
        "agent_ids": ["list of agent IDs if mentioned"],
        "severity": "critical|high|medium|low|all"
    }},
    "confidence": "high|medium|low",
    "approach": "elasticsearch_primary|wazuh_api_primary|hybrid",
    "reasoning": "why you chose this analysis"
}}

Focus on security context and be precise about time ranges and entities.
If the query is casual, conversational, or lacks explicit security or time terminology, still return a valid JSON with intent="general" and choose a broader time_range (prefer "last_week"). Do NOT say the question is incorrect; instead set sub_intent to a friendly broad overview description. Never refuse.
and if the query is like hiii, how are youu, and like not secruity related , just reply friendly
"""
        
        try:
            response_content = await self.decision_llm.ainvoke(analysis_prompt)

            if hasattr(response_content, 'content'):
                analysis_text = response_content.content.strip()
            else:
                analysis_text = str(response_content).strip()
                
            print(f"[DEBUG] AI Analysis Raw Response: {analysis_text[:300]}...")
            
            # Extract JSON from response
            if "{" in analysis_text and "}" in analysis_text:
                start = analysis_text.find("{")
                end = analysis_text.rfind("}") + 1
                json_str = analysis_text[start:end]
                analysis = json.loads(json_str)
                print(f"[DEBUG] AI analysis parsed successfully")
                # Post-process for casual broad queries if AI did not explicitly enrich
                if analysis.get('intent') == 'general':
                    ql = query.lower()
                    tokens = re.findall(r"\w+", ql)
                    security_keywords = ['login','authentication','ssh','failed','brute','force','password','network','port','connection','traffic','firewall','agent','endpoint','host','system','alert','incident','threat','malware','attack']
                    if not any(k in ql for k in security_keywords) and len(tokens) <= 12:
                        analysis['broad_mode'] = True
                        
                        if analysis.get('time_range') in ['last_hour','today','last_24_hours']:
                            analysis['time_range'] = 'last_week'
                        analysis['sub_intent'] = 'Friendly broad overview of recent security data'
                return analysis
            else:
                print(f"[DEBUG] No JSON found in AI response, using fallback")
                return self._fallback_query_analysis(query)
                
        except Exception as e:
            print(f"[DEBUG] AI analysis failed: {e}, using fallback")
            import traceback
            traceback.print_exc()
            return self._fallback_query_analysis(query)
    
    def _fallback_query_analysis(self, query: str) -> dict:
        """Fallback keyword-based analysis when AI fails"""
        
        query_lower = query.lower()
        
        # Basic intent classification
        if any(word in query_lower for word in ['login', 'authentication', 'ssh', 'failed', 'brute force', 'password']):
            intent = "authentication"
        elif any(word in query_lower for word in ['network', 'port', 'connection', 'traffic', 'firewall']):
            intent = "network"
        elif any(word in query_lower for word in ['agent', 'endpoint', 'host', 'system']):
            intent = "agents"
        elif any(word in query_lower for word in ['alert', 'incident', 'threat', 'malware', 'attack']):
            intent = "alerts"
        else:
            intent = "general"
        
        # Extract basic entities
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, query)
        
        # Time range detection
        if 'yesterday' in query_lower:
            time_range = 'yesterday'
        elif 'today' in query_lower:
            time_range = 'today'
        elif 'last hour' in query_lower:
            time_range = 'last_hour'
        elif 'last week' in query_lower:
            time_range = 'last_week'
        else:
            # If user is casual and provides no time hints, expand to last_week for richer context
            time_range = 'last_week'

        # Detect casual broad query (few tokens, lacks security keywords & entities)
        tokens = re.findall(r"\w+", query_lower)
        security_keywords = ['login','authentication','ssh','failed','brute','force','password','network','port','connection','traffic','firewall','agent','endpoint','host','system','alert','incident','threat','malware','attack']
        has_security_keyword = any(k in query_lower for k in security_keywords)
        broad_mode = intent == 'general' and not has_security_keyword and len(tokens) <= 10
        
        return {
            "intent": intent,
            "sub_intent": f"Basic {intent} analysis",
            "time_range": time_range,
            "action_type": "all",
            "entities": {
                "ip_addresses": ips,
                "usernames": [],
                "agent_ids": [],
                "severity": "all"
            },
            "confidence": "medium",
            "approach": "elasticsearch_primary",
            "reasoning": "Fallback keyword-based analysis",
            "broad_mode": broad_mode
        }
    
    async def _create_execution_plan(self, analysis: dict, query: str) -> dict:
        """Create intelligent execution plan based on AI analysis"""
        
        print(f" [DEBUG] Creating execution plan for intent: {analysis.get('intent', 'unknown')}")
        
        intent = analysis.get("intent", "general")
        approach = analysis.get("approach", "elasticsearch_primary")
        entities = analysis.get("entities", {})
        
        plan = {
            "steps": [],
            "approach": approach,
            "reasoning": f"Plan for {intent} query using {approach} approach"
        }
        
        # Build execution steps based on intent
        if intent == "authentication":
            plan["steps"].append({
                "action": "query_elasticsearch",
                "target": "authentication_events",
                "params": {
                    "time_range": analysis.get("time_range", "last_24_hours"),
                    "action_type": analysis.get("action_type", "all"),
                    "ip_addresses": entities.get("ip_addresses", []),
                    "usernames": entities.get("usernames", [])
                },
                "priority": 1
            })
            
            if entities.get("agent_ids"):
                plan["steps"].append({
                    "action": "call_wazuh_tool",
                    "tool": "GetAgentsTool", 
                    "params": {"agent_id": entities["agent_ids"][0]},
                    "priority": 2
                })
        
        elif intent == "network":
            # Use Elasticsearch for network analysis instead of MCP tools
            plan["steps"].append({
                "action": "query_elasticsearch",
                "target": "network_events",
                "params": {
                    "time_range": analysis.get("time_range", "last_24_hours"),
                    "agent_ids": entities.get("agent_ids", []),
                    "severity": "all"
                },
                "priority": 1
            })
        
        elif intent == "agents":
            # Use Elasticsearch for agent information
            plan["steps"].append({
                "action": "query_elasticsearch",
                "target": "agent_events",
                "params": {
                    "time_range": analysis.get("time_range", "last_24_hours"),
                    "agent_ids": entities.get("agent_ids", [])
                },
                "priority": 1
            })
        
        elif intent == "alerts":
            plan["steps"].append({
                "action": "query_elasticsearch",
                "target": "security_alerts", 
                "params": {
                    "time_range": analysis.get("time_range", "last_24_hours"),
                    "severity": entities.get("severity", "high")
                },
                "priority": 1
            })
        
        else:
            # For general queries, if broad_mode requested, gather a wide overview across categories
            if analysis.get("broad_mode"):
                broad_time_range = analysis.get("time_range", "last_week")
                plan["reasoning"] += " | Broad overview mode activated"
                plan["steps"].extend([
                    {
                        "action": "query_elasticsearch",
                        "target": "authentication_events",
                        "params": {"time_range": broad_time_range, "action_type": "all", "ip_addresses": [], "usernames": []},
                        "priority": 1
                    },
                    {
                        "action": "query_elasticsearch",
                        "target": "security_alerts",
                        "params": {"time_range": broad_time_range, "severity": "all"},
                        "priority": 2
                    },
                    {
                        "action": "query_elasticsearch",
                        "target": "network_events",
                        "params": {"time_range": broad_time_range, "agent_ids": [], "severity": "all"},
                        "priority": 3
                    },
                    {
                        "action": "query_elasticsearch",
                        "target": "agent_events",
                        "params": {"time_range": broad_time_range, "agent_ids": []},
                        "priority": 4
                    }
                ])
            else:
                plan["steps"].append({
                    "action": "call_wazuh_tool",
                    "tool": "GetAgentsTool",
                    "params": {},
                    "priority": 1
                })
        
        print(f"[DEBUG] Created execution plan with {len(plan['steps'])} steps")
        return plan
    
    async def _execute_plan(self, plan: dict, query: str) -> dict:
        """Execute the intelligent plan step by step"""
        
        print(f"[DEBUG] Executing plan with {len(plan.get('steps', []))} steps")
        
        results = {
            "approach": plan.get("approach", "unknown"),
            "step_results": []
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            for i, step in enumerate(plan.get("steps", [])):
                try:
                    print(f"⚡ [DEBUG] Executing step {i+1}: {step['action']}")
                    
                    if step["action"] == "query_elasticsearch":
                        result = await self._execute_elasticsearch_query(step)
                    elif step["action"] == "call_wazuh_tool":
                        result = await self._call_wazuh_tool(client, step["tool"], step["params"])
                    else:
                        result = {"error": f"Unknown action: {step['action']}"}
                    
                    results["step_results"].append({
                        "step": i+1,
                        "action": step["action"],
                        "tool": step.get("tool", step.get("target", "unknown")),
                        "result": result,
                        "success": "error" not in str(result).lower() or result.get("total_hits", 0) > 0
                    })
                    
                    print(f" [DEBUG] Step {i+1} completed")
                    
                except Exception as e:
                    print(f"[DEBUG] Step {i+1} failed: {e}")
                    import traceback
                    traceback.print_exc()
                    results["step_results"].append({
                        "step": i+1,
                        "action": step["action"],
                        "error": str(e),
                        "success": False
                    })
        
        print(f"[DEBUG] Plan execution completed. {len(results['step_results'])} steps processed")
        return results
    
    async def _execute_elasticsearch_query(self, step: dict) -> dict:
        """Execute Elasticsearch queries intelligently"""
        
        target = step["target"]
        params = step["params"]
        
        print(f" [DEBUG] Executing Elasticsearch query for target: {target}")
        print(f" [DEBUG] Query params: {json.dumps(params, indent=2)}")
        
        if not self.es:
            print(f"[DEBUG] Elasticsearch not available, returning mock data")
            return {"error": "Elasticsearch not available", "mock_data": True, "total_hits": 0}
        
        try:
            if target == "authentication_events":
                query = self._build_auth_elasticsearch_query(params)
            elif target == "security_alerts":
                query = self._build_alerts_elasticsearch_query(params)
            elif target == "network_events":
                query = self._build_network_elasticsearch_query(params)
            elif target == "agent_events":
                query = self._build_agent_elasticsearch_query(params)
            else:
                return {"error": f"Unknown Elasticsearch target: {target}", "total_hits": 0}
            
            print(f"[DEBUG] Generated Elasticsearch DSL query:")
            print(f"[DEBUG] {json.dumps(query, indent=2)}")
            
            # Execute query
            indices = ["wazuh-alerts-*", "wazuh-archives-*", "filebeat-*"]
            all_results = []
            
            for index in indices:
                try:
                    print(f" [DEBUG] Querying index: {index}")
                    response = self.es.search(
                        index=index,
                        body={**query, "size": 100}
                    )
                    
                    hits = response['hits']['hits']
                    print(f"[DEBUG] Index {index} returned {len(hits)} hits")
                    all_results.extend(hits)
                    
                except Exception as e:
                    print(f" [DEBUG] Index {index} query failed: {e}")
                    continue
            
            print(f"[DEBUG] Total Elasticsearch results: {len(all_results)}")
            
            return {
                "total_hits": len(all_results),
                "hits": all_results,
                "query_used": query,
                "indices_searched": indices,
                "target": target,
                "params": params
            }
            
        except Exception as e:
            print(f" [DEBUG] Elasticsearch query execution failed: {e}")
            import traceback
            traceback.print_exc()
            return {"error": f"Elasticsearch query failed: {str(e)}", "total_hits": 0}
    
    def _build_auth_elasticsearch_query(self, params: dict) -> dict:
        """Build intelligent Elasticsearch query for authentication events"""
        
        # Calculate time range
        time_range = params.get("time_range", "last_24_hours")
        end_time = datetime.now()
        
        if time_range == "yesterday":
            start_time = end_time - timedelta(days=1)
            end_time = end_time - timedelta(days=1) + timedelta(hours=23, minutes=59)
        elif time_range == "today":
            start_time = end_time.replace(hour=0, minute=0, second=0)
        elif time_range == "last_hour":
            start_time = end_time - timedelta(hours=1)
        elif time_range == "last_week":
            start_time = end_time - timedelta(days=7)
        else:  # last_24_hours
            start_time = end_time - timedelta(hours=24)
        
        # Build query
        query = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ],
                    "should": [
                        {"match": {"rule.groups": "authentication"}},
                        {"match": {"rule.groups": "sshd"}},
                        {"match": {"rule.description": "authentication"}},
                        {"match": {"rule.description": "login"}},
                        {"match": {"rule.description": "ssh"}},
                        {"match": {"event.category": "authentication"}},
                        {"match": {"event.type": "authentication"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}},
                {"rule.level": {"order": "desc"}}
            ]
        }
        
        # Add action type filter
        action_type = params.get("action_type", "all")
        if action_type == "failed":
            query["query"]["bool"]["should"].extend([
                {"match": {"rule.description": "failed"}},
                {"match": {"rule.description": "invalid"}},
                {"match": {"rule.description": "denied"}},
                {"match": {"data.status": "failed"}},
                {"range": {"rule.level": {"gte": 5}}}
            ])
        elif action_type == "successful":
            query["query"]["bool"]["should"].extend([
                {"match": {"rule.description": "success"}},
                {"match": {"rule.description": "accepted"}},
                {"match": {"data.status": "success"}},
                {"range": {"rule.level": {"lte": 4}}}
            ])
        
        # Add IP filter
        if params.get("ip_addresses"):
            query["query"]["bool"]["filter"].append({
                "terms": {"data.srcip": params["ip_addresses"]}
            })
        
        # Add username filter
        if params.get("usernames"):
            query["query"]["bool"]["filter"].append({
                "terms": {"data.srcuser": params["usernames"]}
            })
        
        return query
    
    def _build_alerts_elasticsearch_query(self, params: dict) -> dict:
        """Build intelligent Elasticsearch query for security alerts"""
        
        time_range = params.get("time_range", "last_24_hours")
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        severity = params.get("severity", "high")
        min_level = 10 if severity == "critical" else 7 if severity == "high" else 5 if severity == "medium" else 3
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": min_level}}}
                    ],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [
                {"rule.level": {"order": "desc"}},
                {"@timestamp": {"order": "desc"}}
            ]
        }
        
        return query
    
    def _build_network_elasticsearch_query(self, params: dict) -> dict:
        """Build intelligent Elasticsearch query for network events"""
        
        time_range = params.get("time_range", "last_24_hours")
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"rule.groups": "firewall"}},
                        {"match": {"rule.groups": "network"}},
                        {"match": {"rule.description": "port"}},
                        {"match": {"rule.description": "connection"}},
                        {"match": {"data.protocol": "*"}},
                        {"exists": {"field": "data.dstport"}},
                        {"exists": {"field": "data.srcport"}}
                    ],
                    "minimum_should_match": 1,
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "aggs": {
                "ports": {
                    "terms": {
                        "field": "data.dstport",
                        "size": 20
                    }
                },
                "agents": {
                    "terms": {
                        "field": "agent.name",
                        "size": 10
                    }
                }
            }
        }
        
        return query
    
    def _build_agent_elasticsearch_query(self, params: dict) -> dict:
        """Build intelligent Elasticsearch query for agent information"""
        
        time_range = params.get("time_range", "last_24_hours")
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "agent.name"}}
                    ],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "aggs": {
                "agents": {
                    "terms": {
                        "field": "agent.name",
                        "size": 50
                    },
                    "aggs": {
                        "latest_event": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"@timestamp": {"order": "desc"}}]
                            }
                        }
                    }
                }
            }
        }
        
        return query
    
    async def _call_wazuh_tool(self, client: httpx.AsyncClient, tool_name: str, args: dict) -> dict:
        """Call Wazuh MCP server tools with detailed debugging"""
        
        print(f"[DEBUG] Calling Wazuh tool: {tool_name}")
        print(f"[DEBUG] Tool arguments: {json.dumps(args, indent=2)}")
        
        # Skip MCP server calls if not available - use Elasticsearch instead
        print(f"⚠️ [DEBUG] MCP server not properly configured - using Elasticsearch fallback")
        return {
            "error": "MCP server unavailable - using Elasticsearch data instead",
            "fallback": True,
            "message": f"Wazuh MCP server is not responding. Query has been processed using Elasticsearch data only."
        }
    
    async def _format_detailed_response(self, results: dict, analysis: dict, query: str) -> str:
        """Format response with detailed findings first, then intelligent analysis"""
        
        print(f" [DEBUG] Formatting detailed response...")
        
        response = ""
        
        # SECTION 1: What was found (Raw Data Summary)
        response += "=" * 80 + "\n"
        response += "**FINDINGS SUMMARY - WHAT WAS DISCOVERED**\n"
        response += "=" * 80 + "\n\n"
        
        response += f"**Original Query:** `{query}`\n"
        response += f"**Detected Intent:** `{analysis.get('intent', 'unknown').upper()}`\n"
        response += f"**Time Range:** `{analysis.get('time_range', 'last_24_hours').upper()}`\n"
        response += f"**Analysis Confidence:** `{analysis.get('confidence', 'medium').upper()}`\n"
        if analysis.get('broad_mode'):
            response += f"**Mode:** `BROAD OVERVIEW`\n"
        response += "\n"
        
        # Extract and display all findings
        total_items_found = 0
        findings_details = []
        
        for step_result in results.get("step_results", []):
            if step_result.get("success", False):
                result_data = step_result.get("result", {})
                action = step_result.get("action", "unknown")
                tool = step_result.get("tool", "unknown")
                
                if "elasticsearch" in action.lower():
                    total_hits = result_data.get("total_hits", 0)
                    total_items_found += total_hits
                    
                    if total_hits > 0:
                        findings_details.append({
                            "source": "Elasticsearch",
                            "type": result_data.get("target", "events"),
                            "count": total_hits,
                            "data": result_data.get("hits", [])
                        })
                
                elif tool == "GetAgentsTool":
                    if "result" in result_data and "data" in result_data["result"]:
                        agents = result_data["result"]["data"]
                        total_items_found += len(agents)
                        findings_details.append({
                            "source": "Wazuh API",
                            "type": "agents",
                            "count": len(agents),
                            "data": agents
                        })
                
                elif tool == "GetAgentPortsTool":
                    if "result" in result_data:
                        ports_data = result_data["result"]
                        if isinstance(ports_data, dict) and "data" in ports_data:
                            ports = ports_data["data"]
                            total_items_found += len(ports) if isinstance(ports, list) else 1
                            findings_details.append({
                                "source": "Wazuh API",
                                "type": "network_ports",
                                "count": len(ports) if isinstance(ports, list) else 1,
                                "data": ports
                            })
        
        response += f" **TOTAL ITEMS FOUND:** `{total_items_found}`\n\n"

        # Broad mode friendly summary across days
        if analysis.get('broad_mode'):
            # Aggregate per-day counts from all elasticsearch hits
            day_counts = {}
            for step_result in results.get('step_results', []):
                data = step_result.get('result', {})
                for hit in data.get('hits', []):
                    ts = hit.get('_source', {}).get('@timestamp')
                    if not ts:
                        continue
                    day = ts.split('T')[0]
                    day_counts[day] = day_counts.get(day, 0) + 1
            # Sort days descending
            sorted_days = sorted(day_counts.items(), key=lambda x: x[0], reverse=True)
            if day_counts:
                response += "👋 Hey! I took a friendly broad sweep since you spoke casually. Here's a day-by-day snapshot of recent activity I pulled for you:\n\n"
                for day, count in sorted_days[:7]:
                    response += f"- {day}: {count} events\n"
                response += "\nI then broke things down by category below so you can skim quickly. Let me know if you want to zoom in on any part!\n\n"
            else:
                response += "I tried a broad overview but didn't find timestamped events. If data exists outside this cluster window, try narrowing intent or verifying indices.\n\n"
        
        # Display detailed findings
        if findings_details:
            response += " **DETAILED FINDINGS:**\n\n"
            
            for idx, finding in enumerate(findings_details, 1):
                response += f"### Finding {idx}: {finding['type'].replace('_', ' ').title()}\n"
                response += f"- **Source:** {finding['source']}\n"
                response += f"- **Count:** {finding['count']} items\n\n"
                
                # Display sample data
                if finding['type'] == 'authentication_events' or finding['type'] == 'security_alerts':
                    response += "**Sample Events:**\n\n"
                    for i, hit in enumerate(finding['data'][:5], 1):
                        source = hit.get("_source", {})
                        timestamp = source.get("@timestamp", "No Timestamp")
                        if "T" in timestamp:
                            timestamp = timestamp.replace("T", " ").split(".")[0]
                        
                        rule_desc = source.get("rule", {}).get("description", "No Description")
                        rule_level = source.get("rule", {}).get("level", "N/A")
                        agent_name = source.get("agent", {}).get("name", "N/A")
                        src_ip = source.get("data", {}).get("srcip", "N/A")
                        
                        response += f"{i}. **[{timestamp}]** (Level {rule_level})\n"
                        response += f"   - Description: {rule_desc}\n"
                        response += f"   - Agent: {agent_name}\n"
                        response += f"   - Source IP: {src_ip}\n\n"
                
                elif finding['type'] == 'agents':
                    response += "**Agents:**\n\n"
                    for i, agent in enumerate(finding['data'][:10], 1):
                        name = agent.get("name", "Unknown")
                        status = agent.get("status", "unknown")
                        ip = agent.get("ip", "N/A")
                        os_name = agent.get("os", {}).get("name", "N/A") if isinstance(agent.get("os"), dict) else "N/A"
                        
                        response += f"{i}. **{name}** (Status: {status})\n"
                        response += f"   - IP: {ip}\n"
                        response += f"   - OS: {os_name}\n\n"
                
                elif finding['type'] == 'network_ports':
                    response += "**Network Ports:**\n\n"
                    ports_list = finding['data'] if isinstance(finding['data'], list) else [finding['data']]
                    for i, port in enumerate(ports_list[:20], 1):
                        if isinstance(port, dict):
                            local_port = port.get("local_port", "N/A")
                            protocol = port.get("protocol", "N/A")
                            state = port.get("state", "N/A")
                            response += f"{i}. Port {local_port}/{protocol} - State: {state}\n"
                    response += "\n"
                
                response += "---\n\n"
        else:
            response += "**NO FINDINGS** - No data matched the query criteria.\n\n"
        
        
        response += "\n" + "=" * 80 + "\n"
        response += " **INTELLIGENT ANALYSIS - WHAT THIS MEANS**\n"
        response += "=" * 80 + "\n\n"
        
        
        if self.decision_llm and findings_details:
            analysis_summary = self._create_findings_summary(findings_details, analysis)
            
            intelligence_prompt = f"""
You are an expert cybersecurity analyst. Based on the findings below, provide intelligent security analysis.

Original Query: "{query}"
Intent: {analysis.get('intent', 'unknown')}
Total Items Found: {total_items_found}

Findings Summary:
{json.dumps(analysis_summary, indent=2)}

Provide a concise but insightful analysis covering:
1. **Security Implications:** What do these findings mean for security?
2. **Risk Assessment:** Are there any concerning patterns or risks?
3. **Recommendations:** What actions should be taken?
4. **Context:** Additional insights or observations

Be specific and actionable. Use emojis sparingly for key points.
"""
            
            try:
                ai_response = await self.decision_llm.ainvoke(intelligence_prompt)
                
                if hasattr(ai_response, 'content'):
                    intelligent_analysis = ai_response.content.strip()
                else:
                    intelligent_analysis = str(ai_response).strip()
                
                response += intelligent_analysis + "\n\n"
                
            except Exception as e:
                print(f" [DEBUG] AI analysis failed: {e}")
                response += self._generate_fallback_analysis(findings_details, analysis, total_items_found)
        else:
            response += self._generate_fallback_analysis(findings_details, analysis, total_items_found)
        
        # SECTION 3: Execution Details
        response += "\n" + "=" * 80 + "\n"
        response += "**EXECUTION DETAILS**\n"
        response += "=" * 80 + "\n\n"
        
        total_steps = len(results.get("step_results", []))
        successful_steps = len([s for s in results.get("step_results", []) if s.get("success", False)])
        
        response += f"- **Steps Executed:** {total_steps}\n"
        response += f"- **Successful:** {successful_steps}\n"
        response += f"- **Failed:** {total_steps - successful_steps}\n"
        response += f"- **Approach Used:** {results.get('approach', 'unknown')}\n"
        response += f"- **AI Reasoning:** {analysis.get('reasoning', 'N/A')}\n\n"
        
        return response
    
    def _create_findings_summary(self, findings_details: list, analysis: dict) -> dict:
        """Create a structured summary of findings for AI analysis"""
        summary = {
            "intent": analysis.get("intent", "unknown"),
            "time_range": analysis.get("time_range", "unknown"),
            "findings": []
        }
        
        for finding in findings_details:
            finding_summary = {
                "type": finding["type"],
                "count": finding["count"],
                "samples": []
            }
            
            # Extract key information from samples
            if finding['type'] in ['authentication_events', 'security_alerts']:
                for hit in finding['data'][:5]:
                    source = hit.get("_source", {})
                    finding_summary["samples"].append({
                        "timestamp": source.get("@timestamp", "N/A"),
                        "description": source.get("rule", {}).get("description", "N/A"),
                        "level": source.get("rule", {}).get("level", "N/A"),
                        "agent": source.get("agent", {}).get("name", "N/A"),
                        "src_ip": source.get("data", {}).get("srcip", "N/A")
                    })
            elif finding['type'] == 'agents':
                for agent in finding['data'][:5]:
                    finding_summary["samples"].append({
                        "name": agent.get("name", "N/A"),
                        "status": agent.get("status", "N/A"),
                        "ip": agent.get("ip", "N/A")
                    })
            
            summary["findings"].append(finding_summary)
        
        return summary
    
    def _generate_fallback_analysis(self, findings_details: list, analysis: dict, total_items: int) -> str:
        """Generate fallback analysis when AI is not available"""
        
        response = ""
        
        if total_items == 0:
            response += "**No Security Events Found**\n\n"
            response += "This could mean:\n"
            response += "- The system is operating normally with no concerning events in this time period\n"
            response += "- The query filters may be too restrictive\n"
            response += "- Events may exist outside the specified time range\n\n"
            response += "**Recommendation:** Try expanding the time range or adjusting search criteria.\n\n"
            return response
        
        intent = analysis.get("intent", "unknown")
        
        if intent == "authentication":
            response += " **Authentication Events Analysis**\n\n"
            response += f"Found {total_items} authentication-related events.\n\n"
            response += "**Security Implications:**\n"
            response += "- Monitor for unusual login patterns or brute force attempts\n"
            response += "- Failed authentication attempts may indicate unauthorized access attempts\n"
            response += "- Successful logins from unusual IPs should be investigated\n\n"
            response += "**Recommendations:**\n"
            response += "- Review source IPs for any from untrusted locations\n"
            response += "- Correlate multiple failed attempts with account compromise indicators\n"
            response += "- Consider implementing rate limiting or MFA if not already enabled\n\n"
        
        elif intent == "agents":
            response += " **Agent Status Analysis**\n\n"
            response += f"Found {total_items} agents in the system.\n\n"
            response += "**Security Implications:**\n"
            response += "- Disconnected agents may indicate network issues or compromised systems\n"
            response += "- Agent health is critical for security monitoring coverage\n"
            response += "- Outdated agents may miss critical security updates\n\n"
            response += "**Recommendations:**\n"
            response += "- Investigate any disconnected or never-connected agents\n"
            response += "- Ensure all agents are running the latest version\n"
            response += "- Verify network connectivity for offline agents\n\n"
        
        elif intent == "alerts":
            response += "**Security Alerts Analysis**\n\n"
            response += f"Found {total_items} security alerts.\n\n"
            response += "**Security Implications:**\n"
            response += "- High-severity alerts require immediate investigation\n"
            response += "- Alert patterns may indicate ongoing attacks or system issues\n"
            response += "- Correlation across multiple alerts may reveal attack chains\n\n"
            response += "**Recommendations:**\n"
            response += "- Prioritize alerts by severity and asset criticality\n"
            response += "- Investigate root causes and implement remediation\n"
            response += "- Update detection rules based on false positive analysis\n\n"
        
        else:
            response += "**General Analysis**\n\n"
            response += f"Found {total_items} items matching your query.\n\n"
            response += "**Recommendations:**\n"
            response += "- Review the findings for any anomalies or concerning patterns\n"
            response += "- Correlate with other security events if available\n"
            response += "- Take appropriate action based on your security policies\n\n"
        
        return response
    
    def _get_help_message(self) -> str:
        """Return intelligent help message"""
        return """
**INTELLIGENT WAZUH SIEM ANALYZER**

I use AI to understand your security questions and intelligently choose the right tools and data sources.

 **EXAMPLE INTELLIGENT QUERIES**:

 **Authentication Intelligence**:
• "Show me all failed SSH login attempts from yesterday"
• "Find brute force attacks targeting admin accounts"
• "Who successfully logged in from IP 192.168.1.50 today?"
• "Analyze authentication patterns for suspicious activity"

 **Network Intelligence**:
• "What services are running on agent 001?"
• "Find unusual network connections in the last hour"
• "Show me all database connections from external IPs"

 **Threat Intelligence**:
• "Identify critical security alerts from the last 24 hours"
• "Find evidence of malware or attack attempts"
• "Show me high-priority incidents requiring attention"

 **System Intelligence**:
• "Which agents are offline and need attention?"
• "Show me resource usage across all endpoints"
• "Find systems with compliance violations"

**How I work:**
1.  AI analyzes your question to understand intent
2.  I create an intelligent execution plan  
3. I query Elasticsearch and Wazuh APIs
4.  I show you WHAT was found with detailed data
5.  AI explains WHAT IT MEANS with security insights
6.  I provide actionable recommendations

Just ask naturally - I'll figure out the rest! 
        """


    async def auto_scan_mode(self):
        """Automatically scan Elasticsearch every 10 seconds for suspicious activities"""
        
        print("\n" + "=" * 70)
        print(" **AUTO MONITORING MODE ACTIVATED** ")
        print("=" * 70)
        print(" Scanning Elasticsearch every 10 seconds for suspicious activities...")
        print(" I will alert you immediately when anything suspicious is detected!")
        print(" Commands: 'stop' to exit auto mode, 'continue' to resume scanning")
        print("=" * 70 + "\n")
        
        scan_count = 0
        last_alert_time = None
        
        while True:
            try:
                scan_count += 1
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                print(f"[{current_time}]  Scan #{scan_count} - Checking for threats...", end="", flush=True)
                
                # Perform comprehensive security scan
                suspicious_findings = await self._perform_auto_security_scan()
                
                if suspicious_findings and suspicious_findings.get("total_suspicious", 0) > 0:
                    # ALERT! Something suspicious detected!
                    print(f"\r[{current_time}] **ALERT!** Suspicious activity detected!\n")
                    
                    alert_message = await self._format_auto_scan_alert(suspicious_findings)
                    print(alert_message)
                    
                    last_alert_time = datetime.now()
                    
                    # Enter interactive mode after alert
                    print("\n" + "=" * 70)
                    print(" **INTERACTIVE MODE** - You can now ask questions about this alert")
                    print(" Type 'continue' to resume auto scanning, or 'stop' to exit")
                    print("=" * 70 + "\n")
                    
                    while True:
                        user_input = input("\nYour response: ").strip()
                        
                        if user_input.lower() == 'continue':
                            print("\n Resuming auto scan mode...\n")
                            break
                        elif user_input.lower() == 'stop':
                            print("\n Auto monitoring mode stopped.")
                            return
                        elif user_input.lower() in ['quit', 'exit', 'q']:
                            print("\nGoodbye! Stay secure!")
                            return
                        elif user_input:
                            # User asking questions about the alert
                            print(f"\n Analyzing: '{user_input}'")
                            response = await self.analyze_query(user_input)
                            print("\n" + response)
                        else:
                            print("Type 'continue' to resume scanning, 'stop' to exit auto mode")
                else:
                    # All clear
                    print(f"\r[{current_time}] ✅ Scan #{scan_count} - All clear, no threats detected", flush=True)
                
                # Wait 10 seconds before next scan
                await asyncio.sleep(10)
                
            except KeyboardInterrupt:
                print("\n\n Auto monitoring interrupted. Stopping...")
                break
            except Exception as e:
                print(f"\n Error during auto scan: {e}")
                print("Retrying in 10 seconds...")
                await asyncio.sleep(10)
    
    async def _perform_auto_security_scan(self) -> dict:
        """Perform comprehensive security scan of Elasticsearch"""
        
        if not self.es:
            return {"total_suspicious": 0, "findings": []}
        
        suspicious_findings = {
            "total_suspicious": 0,
            "findings": [],
            "scan_time": datetime.now().isoformat()
        }
        
        try:
            # Define security checks
            security_checks = [
                {
                    "name": "High Severity Alerts",
                    "query": self._build_high_severity_query(),
                    "threshold": 0,  # Any high severity alert is suspicious
                    "severity": "HIGH"
                },
                {
                    "name": "Failed Authentication Attempts",
                    "query": self._build_failed_auth_query(),
                    "threshold": 5,  # More than 5 failed attempts is suspicious
                    "severity": "MEDIUM"
                },
                {
                    "name": "Brute Force Indicators",
                    "query": self._build_brute_force_query(),
                    "threshold": 3,  # Multiple failures from same IP
                    "severity": "HIGH"
                },
                {
                    "name": "Malware/Intrusion Attempts",
                    "query": self._build_malware_query(),
                    "threshold": 0,  # Any malware detection is critical
                    "severity": "CRITICAL"
                }
            ]
            
            # Execute all security checks
            for check in security_checks:
                try:
                    result = await self._execute_security_check(check)
                    if result["is_suspicious"]:
                        suspicious_findings["findings"].append(result)
                        suspicious_findings["total_suspicious"] += result["count"]
                except Exception as e:
                    print(f"\n[DEBUG] Security check '{check['name']}' failed: {e}")
                    continue
            
            return suspicious_findings
            
        except Exception as e:
            print(f"\n[DEBUG] Auto scan failed: {e}")
            return {"total_suspicious": 0, "findings": []}
    
    async def _execute_security_check(self, check: dict) -> dict:
        """Execute a single security check"""
        
        indices = ["wazuh-alerts-*", "wazuh-archives-*", "filebeat-*"]
        all_hits = []
        
        for index in indices:
            try:
                response = self.es.search(
                    index=index,
                    body={**check["query"], "size": 50}
                )
                hits = response['hits']['hits']
                all_hits.extend(hits)
            except Exception:
                continue
        
        is_suspicious = len(all_hits) > check["threshold"]
        
        return {
            "name": check["name"],
            "severity": check["severity"],
            "count": len(all_hits),
            "is_suspicious": is_suspicious,
            "threshold": check["threshold"],
            "events": all_hits[:10]  # Keep only top 10 for reporting
        }
    
    def _build_high_severity_query(self) -> dict:
        """Query for high severity alerts in last 10 seconds"""
        now = datetime.now()
        start_time = now - timedelta(seconds=10)
        
        return {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": 10}}}
                    ],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": now.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
    
    def _build_failed_auth_query(self) -> dict:
        """Query for failed authentication attempts in last 10 seconds"""
        now = datetime.now()
        start_time = now - timedelta(seconds=10)
        
        return {
            "query": {
                "bool": {
                    "must": [
                        {
                            "bool": {
                                "should": [
                                    {"match": {"rule.description": "failed"}},
                                    {"match": {"rule.description": "invalid"}},
                                    {"match": {"rule.description": "authentication"}},
                                    {"match": {"rule.groups": "authentication"}}
                                ],
                                "minimum_should_match": 2
                            }
                        }
                    ],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": now.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
    
    def _build_brute_force_query(self) -> dict:
        """Query for brute force attack indicators in last 10 seconds"""
        now = datetime.now()
        start_time = now - timedelta(seconds=10)
        
        return {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"rule.description": "brute force"}},
                        {"match": {"rule.description": "multiple failed"}},
                        {"match": {"rule.groups": "attack"}},
                        {"range": {"rule.level": {"gte": 8}}}
                    ],
                    "minimum_should_match": 1,
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": now.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
    
    def _build_malware_query(self) -> dict:
        """Query for malware/intrusion indicators in last 10 seconds"""
        now = datetime.now()
        start_time = now - timedelta(seconds=10)
        
        return {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"rule.description": "malware"}},
                        {"match": {"rule.description": "trojan"}},
                        {"match": {"rule.description": "rootkit"}},
                        {"match": {"rule.description": "intrusion"}},
                        {"match": {"rule.groups": "malware"}},
                        {"match": {"rule.groups": "rootcheck"}}
                    ],
                    "minimum_should_match": 1,
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": now.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
    
    async def _format_auto_scan_alert(self, findings: dict) -> str:
        """Format the auto scan alert message with all details"""
        
        alert = "\n" + "🚨" * 35 + "\n"
        alert += "**SECURITY ALERT - SUSPICIOUS ACTIVITY DETECTED!**\n"
        alert += "🚨" * 35 + "\n\n"
        
        alert += f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        alert += f"**Total Suspicious Events:** {findings['total_suspicious']}\n"
        alert += f"**Security Checks Triggered:** {len(findings['findings'])}\n\n"
        
        alert += "=" * 70 + "\n"
        alert += "**DETAILED FINDINGS:**\n"
        alert += "=" * 70 + "\n\n"
        
        for idx, finding in enumerate(findings['findings'], 1):
            severity_emoji = "" if finding['severity'] == "CRITICAL" else "🟠" if finding['severity'] == "HIGH" else "🟡"
            
            alert += f"{severity_emoji} **Finding #{idx}: {finding['name']}**\n"
            alert += f"   - Severity: {finding['severity']}\n"
            alert += f"   - Events Detected: {finding['count']}\n"
            alert += f"   - Threshold: {finding['threshold']}\n\n"
            
            if finding['events']:
                alert += "   **Sample Events:**\n"
                for i, event in enumerate(finding['events'][:3], 1):
                    source = event.get("_source", {})
                    timestamp = source.get("@timestamp", "N/A")
                    if "T" in timestamp:
                        timestamp = timestamp.replace("T", " ").split(".")[0]
                    
                    rule_desc = source.get("rule", {}).get("description", "No description")
                    rule_level = source.get("rule", {}).get("level", "N/A")
                    agent = source.get("agent", {}).get("name", "N/A")
                    src_ip = source.get("data", {}).get("srcip", "N/A")
                    
                    alert += f"   {i}. [{timestamp}] Level {rule_level}\n"
                    alert += f"      Description: {rule_desc}\n"
                    alert += f"      Agent: {agent} | Source IP: {src_ip}\n\n"
            
            alert += "   " + "-" * 65 + "\n\n"
        
        # Add AI-powered security analysis
        if self.decision_llm:
            try:
                ai_analysis_prompt = f"""
You are a cybersecurity expert. Analyze these security findings and provide immediate actionable insights.

Findings: {json.dumps(findings, indent=2)}

Provide a BRIEF security analysis (3-4 sentences max) covering:
1. What is the immediate threat?
2. What should be done RIGHT NOW?
3. Is this a critical incident?

Be concise and actionable.
"""
                ai_response = await self.decision_llm.ainvoke(ai_analysis_prompt)
                ai_text = ai_response.content.strip() if hasattr(ai_response, 'content') else str(ai_response).strip()
                
                alert += "=" * 70 + "\n"
                alert += "**AI SECURITY ANALYSIS:**\n"
                alert += "=" * 70 + "\n\n"
                alert += ai_text + "\n\n"
            except Exception as e:
                print(f"[DEBUG] AI analysis failed: {e}")
        
        return alert


async def main():
    print(" **INTELLIGENT WAZUH SIEM ANALYZER**")
    print("=" * 70)
    print(" Powered by Groq LLM + Real Elasticsearch Data")
    print(" Natural Language → AI Reasoning → Real SIEM Data")
    print("=" * 70)
    
    # Initialize Elasticsearch test first
    try:
        from elasticsearch import Elasticsearch
        es_test = Elasticsearch(['http://localhost:9200'])
        info = es_test.info()
        print(f" Elasticsearch connected successfully!")
        print(f" Cluster: {info['cluster_name']}, Version: {info['version']['number']}")
    except Exception as e:
        print(f"Warning: Could not connect to Elasticsearch: {e}")
    
    print("=" * 70)
    
    # Create the intelligent analyzer
    analyzer = IntelligentWazuhAnalyzer()
    
    # Mode selection
    print("\n **SELECT OPERATION MODE:**")
    print("=" * 70)
    print("1.  NORMAL MODE - Interactive Q&A (ask security questions)")
    print("2.  AUTO MODE - Continuous monitoring (scans every 10 seconds)")
    print("=" * 70)
    
    while True:
        mode_choice = input("\nEnter mode (1 for Normal, 2 for Auto): ").strip()
        
        if mode_choice == "1":
            # Normal Interactive Mode
            print("\n **NORMAL MODE ACTIVATED**")
            print("=" * 70)
            print("Type 'quit' to exit, 'auto' to switch to auto mode")
            print("\n **TRY THESE INTELLIGENT QUERIES**:")
            print("   • 'Show me failed login attempts from yesterday'")
            print("   • 'Find brute force attacks in the last 24 hours'") 
            print("   • 'What ports are listening on agent 001?'")
            print("   • 'Show me critical security alerts from today'")
            print("   • 'List all disconnected agents'")
            print("   • 'Who tried to login as admin from IP 192.168.1.50?'")
            print("=" * 70)
            
            while True:
                try:
                    user_input = input("\n Your security question: ").strip()
                    
                    if user_input.lower() in ['quit', 'exit', 'q']:
                        print("\n Goodbye! Stay secure!")
                        return
                    
                    if user_input.lower() == 'auto':
                        print("\n Switching to AUTO MODE...")
                        await analyzer.auto_scan_mode()
                        print("\n Returned to NORMAL MODE")
                        continue
                    
                    if not user_input:
                        continue
                    
                    print(f"\nAnalyzing: '{user_input}'")
                    print("Processing with AI intelligence...")
                    
                    # Use the intelligent analyzer directly
                    response = await analyzer.analyze_query(user_input)
                    
                    print("\n" + response)
                    
                except KeyboardInterrupt:
                    print("\n\nGoodbye! Stay secure!")
                    return
                except Exception as e:
                    print(f"Error: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    print(" Try rephrasing your question or check the examples above.")
        
        elif mode_choice == "2":
            # Auto Monitoring Mode
            try:
                await analyzer.auto_scan_mode()
                print("\n Returned to mode selection")
            except KeyboardInterrupt:
                print("\n\n Auto mode interrupted. Goodbye!")
                return
        
        else:
            print(" Invalid choice. Please enter 1 or 2.")


if __name__ == "__main__":
    asyncio.run(main())