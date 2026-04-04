import os, sys
import mimetypes
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn
from agents.manager import run_pipeline
from db.operations import get_case_stats
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import base64

app = FastAPI(
    title="SATARK AI",
    description="Smart Anti-fraud Technology for Awareness, Reporting & Knowledge",
    version="1.0.0"
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/ui")
def serve_ui():
    return FileResponse("frontend/index.html")

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

class TextRequest(BaseModel):
    text: str
    fraud_amount: Optional[float] = 0
    minutes_since_fraud: Optional[int] = None

@app.get("/")
def root():
    return {"service": "SATARK AI", "status": "online", "version": "1.0.0",
            "helpline": "1930", "portal": "cybercrime.gov.in"}

@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/stats")
def stats():
    return get_case_stats()


@app.post("/analyze")
async def analyze_unified(
    text: Optional[str] = Form(None),
    file: UploadFile | None = File(None),
    fraud_amount: float = Form(0),
    minutes_since_fraud: Optional[int] = Form(None),
):
    try:
        if file is None and (text is None or not text.strip()):
            raise HTTPException(status_code=400, detail="Provide text and/or file")

        if file is None:
            result = await run_pipeline(
                "text",
                {
                    "text": (text or "").strip(),
                    "fraud_amount": fraud_amount,
                    "minutes_since_fraud": minutes_since_fraud,
                },
            )
            return JSONResponse(content=result)

        content = await file.read()
        filename = file.filename or "uploaded_file"
        mime_type = file.content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

        if ext == "apk" or mime_type == "application/vnd.android.package-archive":
            from agents.apk_analyzer.agent import run_static_analysis

            static_results = run_static_analysis(content, filename)
            result = await run_pipeline(
                "apk",
                {
                    "filename": filename,
                    "static_results": static_results,
                    "text": (text or "").strip(),
                },
            )
            return JSONResponse(content=result)

        if mime_type.startswith("audio/"):
            audio_b64 = base64.b64encode(content).decode("utf-8")
            result = await run_pipeline(
                "audio",
                {
                    "audio_b64": audio_b64,
                    "filename": filename,
                    "mime_type": mime_type,
                    "text": (text or "").strip(),
                    "fraud_amount": fraud_amount,
                    "minutes_since_fraud": minutes_since_fraud,
                },
            )
            return JSONResponse(content=result)

        image_b64 = base64.b64encode(content).decode("utf-8")
        result = await run_pipeline(
            "image",
            {
                "image_b64": image_b64,
                "filename": filename,
                "mime_type": mime_type,
                "text": (text or "").strip(),
                "fraud_amount": fraud_amount,
                "minutes_since_fraud": minutes_since_fraud,
            },
        )
        return JSONResponse(content=result)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/text")
async def analyze_text(req: TextRequest):
    try:
        result = await run_pipeline("text", {
            "text": req.text,
            "fraud_amount": req.fraud_amount,
            "minutes_since_fraud": req.minutes_since_fraud,
        })
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/image")
async def analyze_image(
    file: UploadFile = File(...),
    fraud_amount: float = Form(0),
    minutes_since_fraud: Optional[int] = Form(None)
):
    try:
        content = await file.read()
        image_b64 = base64.b64encode(content).decode("utf-8")
        result = await run_pipeline("image", {
            "image_b64": image_b64,
            "filename": file.filename,
            "mime_type": file.content_type or "image/jpeg",
            "fraud_amount": fraud_amount,
            "minutes_since_fraud": minutes_since_fraud,
        })
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/audio")
async def analyze_audio(
    file: UploadFile = File(...),
    fraud_amount: float = Form(0),
    minutes_since_fraud: Optional[int] = Form(None)
):
    try:
        content = await file.read()
        audio_b64 = base64.b64encode(content).decode("utf-8")
        result = await run_pipeline("audio", {
            "audio_b64": audio_b64,
            "filename": file.filename,
            "mime_type": file.content_type or "audio/mp3",
            "fraud_amount": fraud_amount,
            "minutes_since_fraud": minutes_since_fraud,
        })
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/apk")
async def analyze_apk(file: UploadFile = File(...)):
    try:
        content = await file.read()
        from agents.apk_analyzer.agent import run_static_analysis
        static_results = run_static_analysis(content, file.filename)
        result = await run_pipeline("apk", {
            "filename": file.filename,
            "static_results": static_results,
        })
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("api.main:app", host="0.0.0.0", port=port)