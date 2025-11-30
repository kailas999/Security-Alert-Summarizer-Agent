from crewai import Agent, Task, Crew
from crewai.llm import LLM
from dotenv import load_dotenv
from pathlib import Path
import os, sys

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
# 2) Agents
# -------------------------------
summarizer = Agent(
    role="Security Alert Summarizer",
    goal="Extract key facts from the alert (Source, Target, Type, Severity).",
    backstory="You are a precise SOC analyst. You extract facts without fluff.",
    llm=llm,
    verbose=True,
)

mitigator = Agent(
    role="Mitigation Advisor",
    goal="Provide concrete, actionable steps to contain and remediate the threat.",
    backstory="You are a senior incident responder. You give practical advice.",
    llm=llm,
    verbose=True,
)

manager = Agent(
    role="SOC Manager",
    goal="Consolidate findings into a professional SOC Incident Report.",
    backstory="You are the SOC Manager. You review inputs from your team and write the final report for the CISO.",
    llm=llm,
    verbose=True,
)

# -------------------------------
# 3) Input helper
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
# 4) Tasks
# -------------------------------
task_summarize = Task(
    description=f"Summarize this alert:\n{alert_text}",
    agent=summarizer,
    expected_output="Key facts (Source, Target, Type, Severity) in bullet points.",
)

task_mitigate = Task(
    description="Provide mitigation steps based on the summary.",
    agent=mitigator,
    context=[task_summarize],
    expected_output="Immediate actions and next steps in bullet points.",
)

task_report = Task(
    description="Create a final SOC Incident Report incorporating the summary and mitigation plan.",
    agent=manager,
    context=[task_summarize, task_mitigate],
    expected_output="A professional report with: Executive Summary, Technical Details (from Summarizer), Mitigation Plan (from Mitigator), and Conclusion.",
)

# -------------------------------
# 5) Orchestrate
# -------------------------------
crew = Crew(
    agents=[summarizer, mitigator, manager],
    tasks=[task_summarize, task_mitigate, task_report],
    verbose=True,
)

try:
    result = crew.kickoff()
    print("\n================ SOC INCIDENT REPORT ================\n")
    print(result)
    print("\n=====================================================\n")
except Exception as e:
    print(f"Error executing crew: {e}")
    import traceback
    with open("error.log", "w", encoding="utf-8") as f:
        f.write(f"Error: {e}\n")
        traceback.print_exc(file=f)
