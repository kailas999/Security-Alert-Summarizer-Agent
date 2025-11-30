from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
print(f"API Key found: {bool(api_key)}")

try:
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",
        api_key=api_key,
        temperature=0.2,
    )
    print("LLM initialized.")
    response = llm.invoke("Hello, are you working?")
    print("Response received:")
    print(response.content)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
