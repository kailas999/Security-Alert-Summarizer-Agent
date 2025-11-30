from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from crewai import Agent, Task, Crew
from crewai.llm import LLM
from crewai.tools import tool
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = FastAPI(
    title="AI Security Copilot API",
    description="Autonomous SOC Incident Response System API",
    version="1.0.0"
)

# -------------------------------
# 1) Models
# -------------------------------
class AlertRequest(BaseModel):
    alert_text: str
    model: str = "gemini/gemini-2.0-flash"

class ReportResponse(BaseModel):
    status: str
    report: str

# -------------------------------
# 2) LLM & Tools
# -------------------------------
def get_llm(model_name):
    return LLM(
        model=model_name,
        api_key=os.getenv("GEMINI_API_KEY"),
        temperature=0.2,
    )

class ThreatIntelTools:
    @tool("Check IP Reputation")
    def check_ip_reputation(ip_address: str):
        """
        Checks the reputation of a given IP address using simulated Threat Intelligence feeds.
        Returns risk score, malicious status, and geolocation.
        """
        # Mock data logic
        if "45.12.34.7" in ip_address:
            return {
                "ip": ip_address,
                "risk_score": 85,
                "status": "Malicious",
                "geolocation": "Unknown/Proxy",
                "attack_history": ["SSH Brute Force", "Port Scanning"],
                "isp": "BadActor Networks Ltd."
            }
        elif "198.51.100.14" in ip_address:
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
# 3) Crew Logic
# -------------------------------
def run_soc_crew(alert_text: str, model_name: str):
    llm = get_llm(model_name)

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

    # Tasks
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

    crew = Crew(
        agents=[summarizer, threat_intel_agent, mitigator, manager],
        tasks=[task_summarize, task_threat_intel, task_mitigate, task_report],
        verbose=True,
    )

    return crew.kickoff()

# -------------------------------
# 4) Endpoints
# -------------------------------
@app.post("/analyze_alert", response_model=ReportResponse)
async def analyze_alert(request: AlertRequest):
    try:
        result = run_soc_crew(request.alert_text, request.model)
        return ReportResponse(status="success", report=str(result))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_root():
    return {"message": "AI Security Copilot API is running. Use /analyze_alert to process alerts."}
