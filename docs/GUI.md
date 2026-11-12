# Firmware inspection dashboard

Install and start from the project directory:

```sh
python -m pip install ".[web]"
fsa-gui
```

The launcher opens your default browser on an available loopback port. Keep the launcher running while reviewing the report. Ctrl+C stops the server. For a fixed port use `fsa serve`.

Choose or drop one firmware image (up to 128 MiB) and select **Run analysis**. The report shows file identity, sampled entropy, signature offsets, heuristic evidence, kernel strings and analysis limitations. The dashboard scan does not load a CVE feed. Use the CLI with an offline feed for that purpose. English is the default and the language control switches the interface to Arabic.

**Download JSON** saves the complete machine-readable report including every entropy sample. **Print / PDF** uses the browser print dialog. Firmware stays on the local machine. Release verification with VirusTotal applies only to distributed FSA packages.

Select **Inspect ZIP or TAR contents** before scanning to include a file tree and hashes in the JSON report. One dashboard worker runs at a time. **Cancel** stops the request and the server terminates its worker. A 120-second watchdog applies to analysis after intake. Archive inspection requires Linux or Windows.
