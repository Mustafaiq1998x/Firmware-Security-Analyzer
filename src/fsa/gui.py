"""Start a loopback-only dashboard on an available port."""
import socket
import webbrowser


def main():
    try:
        import uvicorn
        from .webapp import app
    except ImportError as exc:
        raise SystemExit("Install the dashboard with: python -m pip install '.[web]'") from exc

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        url = f"http://127.0.0.1:{port}/"
        print(f"Open {url} to inspect firmware. Press Ctrl+C to stop.", flush=True)
        webbrowser.open(url)
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port))
        server.run(sockets=[listener])
