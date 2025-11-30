from crewai import Agent, Task, Crew, LLM
# from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import os
import sys
from pathlib import Path

load_dotenv()

# 1) Load Gemini LLM
# llm = ChatGoogleGenerativeAI(
#     model="gemini-2.0-flash",
#     api_key=os.getenv("GEMINI_API_KEY"),
#     temperature=0.2,
# )
llm = LLM(
    model="gemini/gemini-2.0-flash",
    api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0.2
)

# 2) Define the agent
summarizer_agent = Agent(
    role="Security Alert Summarizer",
    goal=(
        "Read a security alert and produce a concise, actionable summary with:"
        " attack type, source, target, impact, current status, and severity (Low/Medium/High)."
    ),
    backstory=(
        "You are a cybersecurity analyst. You extract key facts and recommend next actions."
    ),
    llm=llm,
    verbose=True,
)

# 3) Read alert text (CLI arg > file > fallback sample)
def get_alert_text():
    # Option A: pass alert directly as CLI arg
    if len(sys.argv) > 1:
        return " ".join(sys.argv[1:])

    # Option B: read from alerts.txt if present
    fpath = Path("alerts.txt")
    if fpath.exists():
        return fpath.read_text(encoding="utf-8")

    # Option C: fallback sample
    return (
        "[ALERT] Example\n"
        "Suspicious port scanning detected from 203.0.113.9 targeting web server.\n"
        "Ports: 22,80,443\n"
        "Status: Rate-limited by firewall\n"
    )

alert_text = get_alert_text()

# 4) Define the task (prompting with a tiny format/rubric)
instructions = f"""
Summarize this security alert clearly and briefly.

Required sections:
- Summary (1–2 lines)
- Key Facts (bullet points: source, target, attempts/ports, time)
- Current Status (blocked/ongoing/unknown)
- Severity (Low/Medium/High) with 1-line reason
- Recommended Actions (2–4 bullets, practical)

Alert:
{alert_text}
"""

summarizer_task = Task(
    description=instructions,
    agent=summarizer_agent,
    expected_output=(
        "A structured summary with the sections listed above. Avoid verbosity."
    ),
)

# 5) Orchestrate and run
crew = Crew(agents=[summarizer_agent], tasks=[summarizer_task], verbose=True)
try:
    result = crew.kickoff()
    print("\n======== FINAL SUMMARY ========\n")
    print(result)
except Exception as e:
    print(f"Error executing crew: {e}")
    import traceback
    traceback.print_exc()
