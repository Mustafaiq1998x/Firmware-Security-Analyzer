"""Optional local-only API and browser dashboard."""
from pathlib import Path
import tempfile

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse

from .analyzer import scan_file

app = FastAPI(
    title="Firmware Security Analyzer",
    version="0.1.2",
    description="Local, read-only static firmware triage API. Findings require manual validation.",
)
API_MAX_UPLOAD_BYTES = 128 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024
DASHBOARD_PATH = Path(__file__).with_name("templates") / "dashboard.html"


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
async def scan(upload: UploadFile = File(...)):
    suffix = Path(upload.filename or "firmware.bin").suffix
    if len(suffix) > 16 or (suffix and not suffix[1:].isalnum()):
        suffix = ".bin"

    temp_path = None
    total = 0
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
            temp_path = Path(handle.name)
            while True:
                chunk = await upload.read(UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > API_MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds {API_MAX_UPLOAD_BYTES} byte limit",
                    )
                handle.write(chunk)
        return scan_file(temp_path, max_file_size=API_MAX_UPLOAD_BYTES)
    except HTTPException:
        raise
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        await upload.close()
