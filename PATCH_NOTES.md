# Phase 2 review candidate

This source snapshot includes the complete project at 54598404f5fb8cf94e697dfe7be8891db9606ad0, the supplied 19-file overlay, and subsequent extraction fixes. Extract into a fresh directory. The previous overlay SHA-256 was dfa518e395e219f2de41aad8d77c2649f4d0f90a12fb75d0954c39df6214863d.

Changes since that overlay include ZIP64 locator recognition, Unicode parent-spelling collision detection, a cumulative TAR extension metadata limit, truncated TAR header handling, and CLI input/report identity checks. The CI workflow matches the baseline. See docs/EXTRACTION.md for the extraction limits and threat model.

## Termux core tests

Run inside the extracted snapshot:

```sh
python -m pip install -e . --no-deps
python -m pip install pytest
python -m pytest -q --ignore=tests/test_webapp.py
```

Keep the existing Git checkout and its uncommitted changes separate until the test result is reviewed. The candidate is pending Termux and Windows verification and its own GitHub Actions run.
