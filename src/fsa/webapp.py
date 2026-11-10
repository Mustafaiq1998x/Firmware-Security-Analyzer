"""Optional local-only API. No authentication: bind to loopback by default."""
from pathlib import Path
import tempfile

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse

from .analyzer import scan_file

app = FastAPI(title="Firmware Security Analyzer", version="0.1.0")
API_MAX_UPLOAD_BYTES = 128 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024


@app.get("/", response_class=HTMLResponse)
def index():
    return """<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">
<title>Firmware Security Analyzer</title><h1>Firmware Security Analyzer</h1>
<p>Local defensive firmware triage API.</p><p><a href=\"/docs\">API documentation</a></p>
<p>POST a firmware file to <code>/scan</code>. Findings are heuristic indicators, not proof.</p>
</html>"""


@app.get("/health")
def health():
    return {"status": "ok", "tool": "FSA"}


@app.post("/scan")
async def scan(upload: UploadFile = File(...)):
    # Stream the upload to a temporary file so the API does not retain a second
    # full-size copy of a potentially large firmware image in memory.
    suffix = Path(upload.filename or "firmware.bin").suffix
    if len(suffix) > 16 or not suffix[1:].isalnum():
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
        # Close before reopening: required for reliable Windows behavior.
        return scan_file(temp_path, max_file_size=API_MAX_UPLOAD_BYTES)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        await upload.close()
