from fastapi import FastAPI, UploadFile, File
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from routes import scan
import uvicorn
import hashlib
from database import init_db

app = FastAPI(title="Sentra by WannaCryptic - Scan Files and URLs for Threats", version="1.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)

init_db()

@app.get("/", summary="Root Redirect to docs",)
async def root():
    return RedirectResponse(url="/docs#/")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8100)
