import os
import json
from dotenv import load_dotenv
from google import genai
from google.genai.types import Tool, GenerateContentConfig, GoogleSearch

load_dotenv()

api_key = os.getenv("API_KEY")

if api_key is None:
    print("Error: API key not found in .env file.")
    exit()

client = genai.Client(api_key=api_key)
model_id = "gemini-2.0-flash"

google_search_tool = Tool(
    google_search=GoogleSearch()
)

url_to_check = input("Enter a URL to check for safety: ")

response = client.models.generate_content(
    model=model_id,
    contents=f"You are an expert in cyber security, specialized in finding phishing urls. Check if the following URL is safe or phishing: {url_to_check}, reply in a json format including these fields: type, name, threatlevel (safe/phishing)",
    config=GenerateContentConfig(
        tools=[google_search_tool],
        response_modalities=["TEXT"],
    )
)

# Extract content from the response
response_content = response.candidates[0].content.parts[0].text

# If the content returned is already in a structured JSON format, print it
try:
    json_response = json.loads(response_content)
    # print(json.dumps(json_response, indent=4))
except json.JSONDecodeError:
    print("Response is not in JSON format. Raw response:")
    print(response_content)

