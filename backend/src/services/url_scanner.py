import os
from google import genai
from dotenv import load_dotenv
from google.genai.types import Tool, GenerateContentConfig, GoogleSearch
import json
import uuid
from datetime import datetime, timezone
from database import SessionLocal
from models import ScanResult

load_dotenv()

api_key = os.getenv("API_KEY")

def check_url_safety(url: str) -> dict:
    """
    Use a third-party service like Google Gemini to analyze URL safety.
    You can replace this with any other safety check or AI model.
    """
    # Initialize Gemini client (replace with your actual API key and model)
    api_key = ""
    client = genai.Client(api_key=api_key)
    model_id = "gemini-2.0-flash"

    google_search_tool = Tool(
        google_search=GoogleSearch()
    )

    # Query Gemini for URL safety
    response = client.models.generate_content(
        model=model_id,
        contents=f"You are an expert in cyber security, specialized in finding phishing urls. Check if the following URL is safe or phishing: {url}, reply in a JSON format including these fields: type, name, threatlevel (safe/phishing)",
        config=GenerateContentConfig(
            tools=[google_search_tool],
            response_modalities=["TEXT"],
        )
    )

    # Extract content from the response
    response_content = response.candidates[0].content.parts[0].text

    try:
        json_response = json.loads(response_content)
    except json.JSONDecodeError:
        json_response = {"error": "Unable to parse the response from the model"}

    return json_response

def save_scan_result(url: str, threat_level: str) -> dict:
    """
    Save the scan result to the database.
    """
    scan_result = ScanResult(
        id=uuid.uuid4().hex,
        name=url,
        type="url",
        filetype="URL",
        timestamp=datetime.now(timezone.utc),
        threat_level=threat_level,
        detected=1 if threat_level == "phishing" else 0,
        total=1
    )
    
    session = SessionLocal()
    session.add(scan_result)
    session.commit()
    session.close()

    return scan_result

def analyze_url(url: str) -> dict:
    """
    Perform a full analysis of the URL: Check its safety and save the result to the database.
    """
    result = check_url_safety(url)
    
    # Check threat level from the model response and save result to the database
    threat_level = result.get("threatlevel", "safe")
    scan_result = save_scan_result(url, threat_level)

    return {
        "url": url,
        "name": url,
        "threatLevel": threat_level,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scanResult": "11"
    }
