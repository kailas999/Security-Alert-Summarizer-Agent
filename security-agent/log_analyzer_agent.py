from crewai import Agent, Task, Crew
from crewai.llm import LLM
from crewai.tools import tool
from dotenv import load_dotenv
from pathlib import Path
import os

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
# 2) Custom Tool: Log Reader
# -------------------------------
class LogTools:
    @tool("Read Log File")
    def read_log_file(file_path: str):
        """
        Reads the content of a specified log file.
        Useful for analyzing system events, authentication failures, and errors.
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return f"Error: File {file_path} not found."
            return path.read_text(encoding="utf-8")
        except Exception as e:
            return f"Error reading file: {e}"

# -------------------------------
# 3) Agents
# -------------------------------
log_analyzer = Agent(
    role="Log Analysis Specialist",
    goal="Analyze raw log files to identify security incidents, anomalies, and suspicious patterns.",
    backstory=(
        "You are an expert in digital forensics and log analysis. "
        "You can spot a brute force attack or privilege escalation attempt from miles away."
    ),
    llm=llm,
    tools=[LogTools.read_log_file],
    verbose=True,
)

manager = Agent(
    role="SOC Manager",
    goal="Review the log analysis and produce a summary report.",
    backstory="You oversee the security operations. You need to know if the logs indicate a breach.",
    llm=llm,
    verbose=True,
)

# -------------------------------
# 4) Tasks
# -------------------------------
task_analyze_logs = Task(
    description=(
        "Read the file 'sample_logs.log'. "
        "Analyze the logs for any suspicious activity, specifically looking for:\n"
        "1. Multiple failed login attempts (Brute Force).\n"
        "2. Unauthorized sudo usage or privilege escalation attempts.\n"
        "3. Any other anomalies.\n\n"
        "Provide a detailed technical analysis of what you found, including timestamps and involved users/IPs."
    ),
    agent=log_analyzer,
    expected_output="Detailed technical analysis of the log file identifying specific security events.",
)

task_report = Task(
    description="Create a Log Analysis Report based on the findings.",
    agent=manager,
    context=[task_analyze_logs],
    expected_output="A structured report summarizing the log analysis findings and recommending actions.",
)

# -------------------------------
# 5) Orchestrate
# -------------------------------
crew = Crew(
    agents=[log_analyzer, manager],
    tasks=[task_analyze_logs, task_report],
    verbose=True,
)

try:
    result = crew.kickoff()
    print("\n================ LOG ANALYSIS REPORT ================\n")
    print(result)
    print("\n=====================================================\n")
except Exception as e:
    print(f"Error executing crew: {e}")
    import traceback
    with open("error.log", "w", encoding="utf-8") as f:
        f.write(f"Error: {e}\n")
        traceback.print_exc(file=f)
