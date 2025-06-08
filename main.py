import json

import openai
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Set your OpenAI API key
openai.api_key = ""

app = FastAPI()

# Allow CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_FLAGS = {
    "redactIPs": True,
    "redactEmails": True,
    "redactKeys": True,
    "redactUsernames": True,
}

def build_redaction_prompt(text: str, flags: dict):
    items = []
    if flags.get("redactIPs"): items.append("IP addresses")
    if flags.get("redactEmails"): items.append("email addresses")
    if flags.get("redactKeys"): items.append("encryption keys, API keys")
    if flags.get("redactUsernames"): items.append("usernames or names")
    
    what_to_redact = ", ".join(items)
    
    prompt = f"""Redact the following sensitive data from the logs: {what_to_redact}.
Keep the log structure and message context unchanged. Here's the log:\n\n{text}"""
    
    return prompt

@app.post("/upload")
async def upload_log(file: UploadFile = File(...), flags: str = Form(None)):
    print(f"Received file: {file.filename}")
    print(f"Received raw flags: {flags}")

    # File validation
    if not file.filename.endswith((".log", ".txt")):
        return JSONResponse(status_code=400, content={"error": "Invalid file type. Only .log or .txt allowed."})
    
    content = await file.read()
    if len(content) > 2 * 1024 * 1024:
        return JSONResponse(status_code=400, content={"error": "File too large. Max size 2MB."})
    
    text = content.decode(errors="ignore")

    # Parse flags safely
    try:
        flag_dict = json.loads(flags) if flags else DEFAULT_FLAGS
        print(f"Parsed flags dict: {flag_dict}")
    except Exception as e:
        print(f"Flags JSON parsing error: {e}, raw flags: {flags}")
        flag_dict = DEFAULT_FLAGS

    prompt = build_redaction_prompt(text, flag_dict)

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )
        redacted = response.choices[0].message.content
        return {"redacted": redacted}
    except Exception as e:
        print(f"OpenAI redaction call failed: {e}")
        return JSONResponse(status_code=500, content={"error": f"Redaction failed: {str(e)}"})


class QARequest(BaseModel):
    question: str
    log: str

@app.post("/ask")
async def ask_log_question(data: QARequest):
    question = data.question
    log = data.log

    prompt = f"""You are a log analysis assistant. Given the following log, answer the user's question.\n
Log:\n{log}\n
Question: {question}
"""

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        return {"answer": response.choices[0].message.content}
    except Exception as e:
        print(f"OpenAI answer generation failed: {e}")
        return JSONResponse(status_code=500, content={"error": f"Answer generation failed: {str(e)}"})
