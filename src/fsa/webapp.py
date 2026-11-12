"""Optional local-only API and browser dashboard."""
from pathlib import Path
import tempfile
from threading import BoundedSemaphore

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles


from .scan_worker import inspect_upload

app = FastAPI(
    title="Firmware Security Analyzer",
    version="0.1.2",
    description="Local, read-only static firmware triage API. Findings require manual validation.",
)
API_MAX_UPLOAD_BYTES = 128 * 1024 * 1024
WORKER_SLOT = BoundedSemaphore(1)
UPLOAD_CHUNK_BYTES = 1024 * 1024
DASHBOARD_PATH = Path(__file__).with_name("templates") / "dashboard.html"


app.mount("/assets", StaticFiles(directory=Path(__file__).with_name("assets")), name="assets")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index():
    try:
        return HTMLResponse(DASHBOARD_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Dashboard asset is unavailable") from exc


@app.get("/health")
def health():
    return {"status": "ok", "tool": "FSA", "version": "0.1.2"}


@app.post("/scan")
async def scan(request: Request, upload: UploadFile = File(...), inspect_archive: bool = Form(False)):
    display_name = (upload.filename or "").replace("\\", "/").split("/")[-1] or "firmware.bin"
    if not WORKER_SLOT.acquire(blocking=False):
        await upload.close()
        raise HTTPException(429, "Another analysis is running")
    total = 0
    try:
        with tempfile.TemporaryDirectory(prefix="fsa-") as temp:
            workspace = Path(temp)
            source = workspace / "input.bin"
            with source.open("xb") as handle:
                while chunk := await upload.read(UPLOAD_CHUNK_BYTES):
                    total += len(chunk)
                    if total > API_MAX_UPLOAD_BYTES:
                        raise HTTPException(413, f"File exceeds {API_MAX_UPLOAD_BYTES} byte limit")
                    handle.write(chunk)
            report = await inspect_upload(source, workspace, API_MAX_UPLOAD_BYTES, inspect_archive,
                                          request.is_disconnected)
            report["input"]["name"] = display_name
            archive = report.get("archive_inspection", {}).get("archive")
            if archive:
                archive["name"] = display_name
            return report
    except TimeoutError as exc:
        raise HTTPException(408, str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        WORKER_SLOT.release()
        await upload.close()
