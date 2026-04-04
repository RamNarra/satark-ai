import os, sys
import asyncio
import json
import mimetypes
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, WebSocket, WebSocketDisconnect
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
from config import PROJECT_ID, LOCATION, GEMINI_LIVE_MODEL

try:
    from google import genai
    from google.genai import types as genai_types
except Exception:
    genai = None  # type: ignore
    genai_types = None  # type: ignore


LIVE_STREAM_INSTRUCTION = (
    "You are SATARK AI, a real-time cyber fraud analyst. "
    "As live audio arrives, return concise TEXT updates with: "
    "RISK (SAFE|MEDIUM|HIGH|CRITICAL), likely scam type, and immediate next action. "
    "When confidence is high, explicitly advise 1930 and cybercrime.gov.in."
)


live_client = (
    genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
    if genai is not None
    else None
)

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


@app.websocket("/stream")
async def stream_audio(websocket: WebSocket):
    await websocket.accept()

    if live_client is None or genai_types is None:
        await websocket.send_json({"type": "error", "message": "google-genai live SDK is unavailable"})
        await websocket.close(code=1011)
        return

    model_name = GEMINI_LIVE_MODEL
    mime_type = "audio/webm"
    stop_event = asyncio.Event()

    try:
        async with live_client.aio.live.connect(
            model=model_name,
            config={
                "response_modalities": ["AUDIO"],
                "input_audio_transcription": {},
                "output_audio_transcription": {},
            },
        ) as session:
            await session.send_client_content(
                turns={"role": "user", "parts": [{"text": LIVE_STREAM_INSTRUCTION}]},
                turn_complete=False,
            )

            async def receive_browser_audio():
                nonlocal mime_type
                while not stop_event.is_set():
                    message = await websocket.receive()

                    if message.get("type") == "websocket.disconnect":
                        stop_event.set()
                        break

                    if message.get("bytes") is not None:
                        chunk = message["bytes"]
                        if chunk:
                            await session.send_realtime_input(
                                audio=genai_types.Blob(data=chunk, mime_type=mime_type)
                            )
                        continue

                    text_msg = (message.get("text") or "").strip()
                    if not text_msg:
                        continue

                    try:
                        payload = json.loads(text_msg)
                    except Exception:
                        await session.send_realtime_input(text=text_msg)
                        continue

                    event_type = payload.get("type")
                    if event_type == "config" and payload.get("mime_type"):
                        mime_type = str(payload.get("mime_type"))
                    elif event_type == "audio_end":
                        await session.send_realtime_input(audio_stream_end=True)
                    elif event_type == "text" and payload.get("text"):
                        await session.send_realtime_input(text=str(payload.get("text")))

                stop_event.set()

            async def forward_live_analysis():
                while not stop_event.is_set():
                    async for chunk in session.receive():
                        if chunk.text:
                            await websocket.send_json({"type": "analysis", "text": chunk.text})
                        if (
                            chunk.server_content
                            and chunk.server_content.input_transcription
                            and chunk.server_content.input_transcription.text
                        ):
                            await websocket.send_json(
                                {
                                    "type": "analysis",
                                    "text": f"CALLER: {chunk.server_content.input_transcription.text}",
                                }
                            )
                        if (
                            chunk.server_content
                            and chunk.server_content.output_transcription
                            and chunk.server_content.output_transcription.text
                        ):
                            await websocket.send_json(
                                {
                                    "type": "analysis",
                                    "text": f"SATARK: {chunk.server_content.output_transcription.text}",
                                }
                            )
                        if chunk.server_content and chunk.server_content.turn_complete:
                            await websocket.send_json({"type": "turn_complete"})
                        if stop_event.is_set():
                            break

                stop_event.set()

            in_task = asyncio.create_task(receive_browser_audio())
            out_task = asyncio.create_task(forward_live_analysis())

            done, pending = await asyncio.wait(
                [in_task, out_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            stop_event.set()

            for task in pending:
                task.cancel()

            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, WebSocketDisconnect):
                    await websocket.send_json({"type": "error", "message": str(exc)})

            try:
                await session.send_realtime_input(audio_stream_end=True)
            except Exception:
                pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("api.main:app", host="0.0.0.0", port=port)