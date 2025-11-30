import streamlit as st
from crewai import Agent, Task, Crew
from crewai.llm import LLM
from crewai.tools import tool
from dotenv import load_dotenv
import os
import time
import sys
# Import our new utils
from utils import generate_pdf_report, create_threat_graph, generate_audio_summary

# Load environment variables
load_dotenv()

# Page Config
st.set_page_config(
    page_title="SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------
# Custom CSS (Cyberpunk Theme)
# -------------------------------
st.markdown("""
<style>
    /* Main Background */
    .stApp {
        background-color: #050505;
        color: #00FF41;
        font-family: 'Courier New', Courier, monospace;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #0A0A0A;
        border-right: 1px solid #00FF41;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #00FF41 !important;
        text-shadow: 0 0 5px #00FF41;
    }
    
    /* Buttons */
    .stButton>button {
        background-color: #000000;
        color: #00FF41;
        border: 1px solid #00FF41;
        border-radius: 0px;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        background-color: #00FF41;
        color: #000000;
        box-shadow: 0 0 10px #00FF41;
    }
    
    /* Inputs */
    .stTextArea>div>div>textarea {
        background-color: #000000;
        color: #00FF41;
        border: 1px solid #333;
    }
    
    /* Metrics */
    [data-testid="stMetricValue"] {
        color: #FF0055;
        text-shadow: 0 0 5px #FF0055;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #0A0A0A;
        border: 1px solid #333;
        color: #888;
    }
    .stTabs [aria-selected="true"] {
        background-color: #00FF41 !important;
        color: #000 !important;
    }
</style>
""", unsafe_allow_html=True)

# -------------------------------
# 1) LLM Setup
# -------------------------------
@st.cache_resource
def get_llm(model_name, temp):
    return LLM(
        model=model_name,
        api_key=os.getenv("GEMINI_API_KEY"),
        temperature=temp,
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
# 3) Agents Definition
# -------------------------------
def create_crew(alert_text, llm):
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

    return Crew(
        agents=[summarizer, threat_intel_agent, mitigator, manager],
        tasks=[task_summarize, task_threat_intel, task_mitigate, task_report],
        verbose=True,
    )

# -------------------------------
# 4) Main UI Logic
# -------------------------------

# Sidebar
with st.sidebar:
    st.title("🛡️ SOC COMMAND")
    st.markdown("---")
    
    st.subheader("⚙️ System Config")
    model_choice = st.selectbox(
        "AI Model",
        ["gemini/gemini-2.0-flash", "gemini/gemini-1.5-flash"],
        index=0
    )
    temperature = st.slider("Creativity (Temp)", 0.0, 1.0, 0.2)
    
    st.markdown("---")
    st.subheader("📡 Auto-Pilot")
    auto_pilot = st.toggle("Enable Log Watcher", value=False)
    if auto_pilot:
        st.caption("Monitoring `sample_logs.log`...")
        
    st.markdown("---")
    st.info("System Status: ONLINE")

# Main Content
st.title("🚨 SECURITY INCIDENT RESPONSE")
st.markdown("### Autonomous Threat Analysis & Mitigation System")

# Tabs
tab1, tab2, tab3 = st.tabs(["🔴 Live Operations", "🕸️ Threat Graph", "📂 Reports & Artifacts"])

# Initialize Session State
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "source_ip" not in st.session_state:
    st.session_state.source_ip = "Unknown"

llm = get_llm(model_choice, temperature)

with tab1:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Input Stream")
        alert_input = st.text_area(
            "Security Alert / Log Entry",
            height=150,
            placeholder="[ALERT] SSH Brute Force detected from IP 45.12.34.7..."
        )
        
        if st.button("🚀 INITIATE RESPONSE", type="primary", use_container_width=True):
            if not alert_input:
                st.warning("NO DATA RECEIVED.")
            else:
                with st.status("🤖 AGENTS ACTIVE...", expanded=True) as status:
                    st.write("🔍 Summarizer: Extracting IOCs...")
                    # In a real app, we'd use callbacks to update this live
                    crew = create_crew(alert_input, llm)
                    result = crew.kickoff()
                    st.session_state.analysis_result = str(result)
                    
                    # Extract IP for graph (simple heuristic for demo)
                    import re
                    ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', alert_input)
                    if ip_match:
                        st.session_state.source_ip = ip_match.group(0)
                    
                    status.update(label="✅ THREAT NEUTRALIZED (Analysis Complete)", state="complete", expanded=False)
                
                st.success("Analysis Complete")

    with col2:
        st.subheader("Live Metrics")
        # Mock metrics for visual flair
        st.metric(label="Threat Level", value="CRITICAL", delta="High")
        st.metric(label="Active Agents", value="4", delta="Online")
        st.metric(label="System Load", value="12%", delta="-2%")

    # Display Result
    if st.session_state.analysis_result:
        st.markdown("---")
        st.subheader("📝 Incident Report")
        st.markdown(st.session_state.analysis_result)

with tab2:
    st.subheader("Interactive Threat Map")
    if st.session_state.analysis_result:
        # Generate Graph
        graph = create_threat_graph(st.session_state.source_ip, "Corporate_Server_01", "Brute Force")
        if graph:
            st.graphviz_chart(graph)
        else:
            st.error("Could not generate graph.")
    else:
        st.info("Run analysis to generate threat map.")

with tab3:
    st.subheader("Export & Dissemination")
    if st.session_state.analysis_result:
        col_a, col_b = st.columns(2)
        
        with col_a:
            st.markdown("#### 📄 PDF Report")
            pdf_file = generate_pdf_report(st.session_state.analysis_result)
            if pdf_file:
                with open(pdf_file, "rb") as f:
                    st.download_button(
                        label="⬇️ Download PDF",
                        data=f,
                        file_name="soc_report.pdf",
                        mime="application/pdf"
                    )
        
        with col_b:
            st.markdown("#### 🎧 Audio Briefing")
            if st.button("Generate Audio Summary"):
                audio_file = generate_audio_summary(st.session_state.analysis_result[:500]) # Limit chars for speed
                if audio_file:
                    st.audio(audio_file)
    else:
        st.info("No report available to export.")

# Auto-Pilot Logic (Simple Implementation)
if auto_pilot:
    # Check for new logs (Mocking the behavior for demo)
    # In a real app, this would be a loop or use st.empty()
    pass
