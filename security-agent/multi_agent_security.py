from crewai import Agent, Task, Crew
from crewai.llm import LLM
from dotenv import load_dotenv
from pathlib import Path
import os, sys

load_dotenv()

# -------------------------------
# 1) LLM (Gemini via LiteLLM name)
# -------------------------------
llm = LLM(
    model="gemini/gemini-2.0-flash",  # or gemini-1.5-pro
    api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0.2,
)

# -------------------------------
# 2) Agents
# -------------------------------
summarizer = Agent(
    role="Security Alert Summarizer",
    goal=("Extract key facts from a given security alert and produce a short, "
          "actionable summary including type, source, target, status, and severity."),
    backstory=("You are a SOC analyst who writes crisp incident summaries for on-call teams. "
               "You prefer bullet points and unambiguous facts."),
    llm=llm,
    verbose=True,
)

mitigator = Agent(
    role="Mitigation Advisor",
    goal=("Given a security alert (and/or its summary), provide concrete, prioritized remediation steps. "
          "Always include quick actions and follow-ups."),
    backstory=("You are a senior incident responder. You recommend practical, least-privilege, auditable actions. "
               "You avoid generic advice and tailor steps to the alert details."),
    llm=llm,
    verbose=True,
)

# -------------------------------
# 3) Input helper
# -------------------------------
def get_alert_text():
    # A) Inline via CLI: python multi_agent_security.py "<alert text>"
    if len(sys.argv) > 1:
        return " ".join(sys.argv[1:])

    # B) From file alerts.txt
    f = Path("alerts.txt")
    if f.exists():
        return f.read_text(encoding="utf-8")

    # C) Fallback sample
    return (
        "[ALERT] 2025-11-29 19:57 IST\n"
        "Multiple failed SSH login attempts detected.\n"
        "Source IP: 45.12.34.7\n"
        "Target: Ubuntu-Prod-Server-04\n"
        "Attempts: 56\n"
        "Status: Blocked by Fail2Ban\n"
    )

alert_text = get_alert_text()

# -------------------------------
# 4) Tasks (Mitigation uses Summary as context)
# -------------------------------
summary_instructions = f"""
You will summarize a security alert.

Format your output with EXACTLY these sections:

Summary: (1–2 lines, plain English)
Key Facts:
- Source:
- Target:
- Vector/Type:
- Time/Window:
- Attempts/Ports:
Current Status: (blocked/ongoing/unknown)
Severity: (Low/Medium/High) + one-line reason
"""

task_summarize = Task(
    description=summary_instructions + "\n\nAlert:\n" + alert_text,
    agent=summarizer,
    expected_output=("A short, structured summary using the exact sections above. "
                     "Avoid verbosity, no extra sections."),
)

mitigation_instructions = """
Using the alert + its summary, produce mitigation guidance.

Output format:

Immediate Actions (now):
- step 1
- step 2
- step 3

Next Steps (follow-up):
- step 1
- step 2

Verification:
- How to confirm the threat is mitigated

Notes:
- Any caution, dependencies, known risks
"""

task_mitigate = Task(
    description=mitigation_instructions,
    agent=mitigator,
    # CRITICAL: consume the summary as context for better mitigation
    context=[task_summarize],
    expected_output=("Clear, actionable steps tailored to the alert. "
                     "Avoid generic advice. Keep it concise but specific."),
)

# -------------------------------
# 5) Orchestrate & run
# -------------------------------
crew = Crew(
    agents=[summarizer, mitigator],
    tasks=[task_summarize, task_mitigate],
    verbose=True,   # set False for quiet
)

try:
    result = crew.kickoff()

    print("\n================ FINAL REPORT ================\n")
    print(">>> SUMMARY\n")
    print(task_summarize.output.raw if task_summarize.output else "(no summary)")
    print("\n>>> MITIGATION\n")
    print(task_mitigate.output.raw if task_mitigate.output else "(no mitigation)")
    print("\n=============================================\n")
except Exception as e:
    print(f"Error executing crew: {e}")
    import traceback
    with open("error.log", "w", encoding="utf-8") as f:
        f.write(f"Error: {e}\n")
        traceback.print_exc(file=f)
