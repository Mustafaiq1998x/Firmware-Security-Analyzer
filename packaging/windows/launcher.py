"""Entry point for the portable Windows application."""
import multiprocessing


if __name__ == "__main__":
    multiprocessing.freeze_support()
    import sys
    from pathlib import Path

    if len(sys.argv) == 4 and sys.argv[1] == "--check-build":
        import tkinter as tk
        from fsa.desktop import Inspector
        from fsa.reporting import write_html, write_json

        root = tk.Tk()
        window = Inspector(root)
        window.start(sys.argv[2])

        def finish():
            if window.process is not None:
                root.after(150, finish)
                return
            if window.report:
                output = Path(sys.argv[3])
                write_json(window.report, output)
                write_html(window.report, output.with_suffix(".html"))
            window.close()

        root.after(150, finish)
        root.mainloop()
    else:
        from fsa.desktop import main
        main()
