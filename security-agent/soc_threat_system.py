from crewai import Agent, Task, Crew
from crewai.llm import LLM
from crewai.tools import tool
from dotenv import load_dotenv
from pathlib import Path
import os, sys
import random

load_dotenv()

# -------------------------------
# 1) LLM
# -------------------------------
llm = LLM(
    model="gemini/gemini-2.0-flash",
    api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0.2,
)

# -------------------------------
# 2) Custom Tool: Threat Intel
# -------------------------------
class ThreatIntelTools:
    @tool("Check IP Reputation")
    def check_ip_reputation(ip_address: str):
        """
        Checks the reputation of a given IP address using simulated Threat Intelligence feeds.
        Returns risk score, malicious status, and geolocation.
        """
        # Simulated logic for demo purposes
        # In a real scenario, you would call AbuseIPDB or VirusTotal APIs here.
        
        print(f"\n[ThreatIntelTool] Checking IP: {ip_address}...\n")
        
        # Mock data based on the sample IP in alerts.txt (45.12.34.7)
        if "45.12.34.7" in ip_address:
            return {
                "ip": ip_address,
                "risk_score": 85,
                "status": "Malicious",
                "geolocation": "Unknown/Proxy",
                "attack_history": ["SSH Brute Force", "Port Scanning"],
                "isp": "BadActor Networks Ltd."
            }
        elif "198.51.100.14" in ip_address: # Example from CLI test
             return {
                "ip": ip_address,
                "risk_score": 92,
                "status": "High Risk",
                "geolocation": "Eastern Europe",
                "attack_history": ["Data Exfiltration", "Ransomware C2"],
                "isp": "Bulletproof Hosting Inc."
            }
        else:
            return {
                "ip": ip_address,
                "risk_score": 10,
                "status": "Benign",
                "geolocation": "US",
                "attack_history": [],
                "isp": "Cloud Provider Inc."
            }

# -------------------------------
# 3) Agents
# -------------------------------
summarizer = Agent(
    role="Security Alert Summarizer",
    goal="Extract key facts (Source IP, Target, Type).",
    backstory="You are a SOC analyst. You extract facts precisely.",
    llm=llm,
    verbose=True,
)

threat_intel_agent = Agent(
    role="Threat Intelligence Analyst",
    goal="Investigate source IPs and provide reputation/risk data.",
    backstory="You are a Threat Intel specialist. You use tools to check if an IP is malicious.",
    llm=llm,
    tools=[ThreatIntelTools.check_ip_reputation],
    verbose=True,
)

mitigator = Agent(
    role="Mitigation Advisor",
    goal="Provide remediation steps considering the threat intelligence.",
    backstory="You are a senior incident responder. You tailor actions based on IP risk.",
    llm=llm,
    verbose=True,
)

manager = Agent(
    role="SOC Manager",
    goal="Consolidate all findings into a final SOC Incident Report.",
    backstory="You are the SOC Manager. You generate the final report.",
    llm=llm,
    verbose=True,
)

# -------------------------------
# 4) Input helper
# -------------------------------
def get_alert_text():
    if len(sys.argv) > 1:
        return " ".join(sys.argv[1:])
    
    f = Path("alerts.txt")
    if f.exists():
        return f.read_text(encoding="utf-8")
    
    return "No alert provided."

alert_text = get_alert_text()

# -------------------------------
# 5) Tasks
# -------------------------------
task_summarize = Task(
    description=f"Summarize this alert and extract the Source IP:\n{alert_text}",
    agent=summarizer,
    expected_output="Summary with Source IP clearly identified.",
)

task_threat_intel = Task(
    description="Analyze the Source IP from the summary using the 'Check IP Reputation' tool.",
    agent=threat_intel_agent,
    context=[task_summarize],
    expected_output="Threat Intelligence Report including Risk Score, Status, and ISP.",
)

task_mitigate = Task(
    description="Provide mitigation steps based on the summary and threat intelligence.",
    agent=mitigator,
    context=[task_summarize, task_threat_intel],
    expected_output="Mitigation plan tailored to the specific threat level.",
)

task_report = Task(
    description="Create a final SOC Incident Report incorporating Summary, Threat Intel, and Mitigation.",
    agent=manager,
    context=[task_summarize, task_threat_intel, task_mitigate],
    expected_output="Professional SOC Report with dedicated sections for Threat Intel and Mitigation.",
)

# -------------------------------
# 6) Orchestrate
# -------------------------------
crew = Crew(
    agents=[summarizer, threat_intel_agent, mitigator, manager],
    tasks=[task_summarize, task_threat_intel, task_mitigate, task_report],
    verbose=True,
)

try:
    result = crew.kickoff()
    print("\n================ SOC THREAT REPORT ================\n")
    print(result)
    print("\n===================================================\n")
except Exception as e:
    print(f"Error executing crew: {e}")
    import traceback
    with open("error.log", "w", encoding="utf-8") as f:
        f.write(f"Error: {e}\n")
        traceback.print_exc(file=f)
