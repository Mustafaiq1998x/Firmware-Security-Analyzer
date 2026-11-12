import io
import tarfile
import zipfile

import pytest
from fsa.extraction import ExtractionError, ExtractionLimits, safe_extract_archive


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)


def test_extracts_zip_and_hashes(tmp_path):
    archive = tmp_path / "ok.zip"
    make_zip(archive, [("etc/config.txt", b"hello"), ("empty/", b"")])
    out = tmp_path / "out"
    report = safe_extract_archive(archive, out)
    assert (out / "etc/config.txt").read_bytes() == b"hello"
    assert report["summary"]["files"] == 1
    assert report["entries"][0]["sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:/windows", "\\\\server\\share", "a/../../b"])
def test_rejects_traversal_paths(tmp_path, name):
    archive = tmp_path / "bad.zip"
    make_zip(archive, [(name, b"x")])
    out = tmp_path / "out"
    with pytest.raises(ExtractionError):
        safe_extract_archive(archive, out)
    assert not out.exists()


def test_rejects_duplicate_and_case_collision(tmp_path):
    archive = tmp_path / "dup.zip"
    make_zip(archive, [("Config", b"a"), ("config", b"b")])
    with pytest.raises(ExtractionError, match="duplicate"):
        safe_extract_archive(archive, tmp_path / "out")


def test_rejects_compression_bomb_ratio(tmp_path):
    archive = tmp_path / "bomb.zip"
    make_zip(archive, [("zeros.bin", b"0" * 100_000)])
    with pytest.raises(ExtractionError, match="compression ratio"):
        safe_extract_archive(archive, tmp_path / "out", ExtractionLimits(max_compression_ratio=2))


def test_enforces_actual_total_bytes_and_cleans_up(tmp_path):
    archive = tmp_path / "total.zip"
    make_zip(archive, [("a.bin", b"a" * 10), ("b.bin", b"b" * 10)])
    out = tmp_path / "out"
    with pytest.raises(ExtractionError, match="total extracted"):
        safe_extract_archive(archive, out, ExtractionLimits(max_total_bytes=15, max_compression_ratio=1000))
    assert not out.exists()


def test_rejects_file_count_limit(tmp_path):
    archive = tmp_path / "many.zip"
    make_zip(archive, [("a", b"1"), ("b", b"2")])
    with pytest.raises(ExtractionError, match="file count"):
        safe_extract_archive(archive, tmp_path / "out", ExtractionLimits(max_files=1))


def test_rejects_zip_symlink(tmp_path):
    archive = tmp_path / "link.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "../../outside")
    with pytest.raises(ExtractionError, match="links"):
        safe_extract_archive(archive, tmp_path / "out")


def test_extracts_tar_and_rejects_tar_symlink(tmp_path):
    archive = tmp_path / "ok.tar"
    with tarfile.open(archive, "w") as tf:
        data = b"firmware"
        info = tarfile.TarInfo("root/image.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    out = tmp_path / "out"
    report = safe_extract_archive(archive, out)
    assert (out / "root/image.bin").read_bytes() == b"firmware"
    assert report["format"] == "tar"

    bad = tmp_path / "link.tar"
    with tarfile.open(bad, "w") as tf:
        info = tarfile.TarInfo("escape")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        tf.addfile(info)
    with pytest.raises(ExtractionError, match="special TAR"):
        safe_extract_archive(bad, tmp_path / "bad-out")


def test_rejects_nonempty_destination(tmp_path):
    archive = tmp_path / "ok.zip"
    make_zip(archive, [("a", b"x")])
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep").write_text("keep")
    with pytest.raises(ExtractionError, match="destination"):
        safe_extract_archive(archive, out)
    assert (out / "keep").read_text() == "keep"


def test_rejects_unsupported_format(tmp_path):
    archive = tmp_path / "raw.bin"
    archive.write_bytes(b"not an archive")
    with pytest.raises(ExtractionError, match="unsupported"):
        safe_extract_archive(archive, tmp_path / "out")


def test_rejects_archive_size_limit(tmp_path):
    archive = tmp_path / "big.zip"
    make_zip(archive, [("a", b"x")])
    with pytest.raises(ExtractionError, match="archive size"):
        safe_extract_archive(archive, tmp_path / "out", ExtractionLimits(max_archive_bytes=1))


def test_rejects_single_file_actual_size_limit(tmp_path):
    archive = tmp_path / "file.zip"
    make_zip(archive, [("a", b"0123456789")])
    with pytest.raises(ExtractionError, match="single-file"):
        safe_extract_archive(archive, tmp_path / "out", ExtractionLimits(max_file_bytes=5, max_compression_ratio=100))
    assert not (tmp_path / "out").exists()


def test_rejects_tar_traversal_and_hardlink(tmp_path):
    bad = tmp_path / "traversal.tar"
    with tarfile.open(bad, "w") as tf:
        data = b"x"
        info = tarfile.TarInfo("../../outside")
        info.size = 1
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(ExtractionError, match="path traversal"):
        safe_extract_archive(bad, tmp_path / "out")

    hard = tmp_path / "hard.tar"
    with tarfile.open(hard, "w") as tf:
        info = tarfile.TarInfo("hardlink")
        info.type = tarfile.LNKTYPE
        info.linkname = "target"
        tf.addfile(info)
    with pytest.raises(ExtractionError, match="special TAR"):
        safe_extract_archive(hard, tmp_path / "hard-out")


def test_nested_archives_are_not_recursively_extracted(tmp_path):
    inner = tmp_path / "inner.zip"
    make_zip(inner, [("payload.txt", b"nested")])
    archive = tmp_path / "outer.zip"
    make_zip(archive, [("inner.zip", inner.read_bytes())])
    out = tmp_path / "out"
    safe_extract_archive(archive, out)
    assert zipfile.is_zipfile(out / "inner.zip")
    assert not (out / "payload.txt").exists()


def test_rejects_symlink_archive_source(tmp_path):
    archive = tmp_path / "real.zip"
    make_zip(archive, [("a", b"x")])
    link = tmp_path / "link.zip"
    try:
        link.symlink_to(archive)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ExtractionError, match="regular"):
        safe_extract_archive(link, tmp_path / "out")


@pytest.mark.parametrize("name", ["CON", "NUL.txt", "bad:name", "trailing. "])
def test_rejects_windows_reserved_or_ambiguous_names(tmp_path, name):
    archive = tmp_path / "windows.zip"
    make_zip(archive, [(name, b"x")])
    with pytest.raises(ExtractionError):
        safe_extract_archive(archive, tmp_path / "out")


def test_counts_implicit_directories_and_enforces_depth(tmp_path):
    archive = tmp_path / "deep.zip"
    make_zip(archive, [("a/b/c/d/file.bin", b"x")])
    with pytest.raises(ExtractionError, match="path depth"):
        safe_extract_archive(archive, tmp_path / "depth-out", ExtractionLimits(max_depth=3))
    with pytest.raises(ExtractionError, match="directory count"):
        safe_extract_archive(archive, tmp_path / "dirs-out", ExtractionLimits(max_directories=2))


def test_supports_conventional_tar_dot_prefix(tmp_path):
    archive = tmp_path / "dot-prefix.tar"
    with tarfile.open(archive, "w") as tf:
        root = tarfile.TarInfo("./")
        root.type = tarfile.DIRTYPE
        tf.addfile(root)
        data = b"config"
        info = tarfile.TarInfo("./etc/config")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    out = tmp_path / "out"
    safe_extract_archive(archive, out)
    assert (out / "etc/config").read_bytes() == b"config"


def test_rejects_dotdot_after_tar_prefix_normalization(tmp_path):
    archive = tmp_path / "dot-traversal.tar"
    with tarfile.open(archive, "w") as tf:
        data = b"x"
        info = tarfile.TarInfo("./../../outside")
        info.size = 1
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(ExtractionError, match="path traversal"):
        safe_extract_archive(archive, tmp_path / "out")


@pytest.mark.parametrize("kwargs", [{"max_seconds": float("nan")}, {"max_seconds": float("inf")},
                                     {"max_compression_ratio": float("nan")}])
def test_rejects_non_finite_limits(kwargs):
    with pytest.raises(ValueError, match="finite"):
        ExtractionLimits(**kwargs)


def test_failure_preserves_preexisting_empty_destination_directory(tmp_path):
    archive = tmp_path / "bad.zip"
    make_zip(archive, [("../escape", b"x")])
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ExtractionError):
        safe_extract_archive(archive, out)
    assert out.is_dir()
    assert list(out.iterdir()) == []


def test_destination_parent_must_exist(tmp_path):
    archive = tmp_path / "ok.zip"
    make_zip(archive, [("a", b"x")])
    with pytest.raises(ExtractionError, match="parent directory"):
        safe_extract_archive(archive, tmp_path / "missing" / "out")


def test_zip_entry_count_preflight_runs_before_infolist(tmp_path, monkeypatch):
    archive = tmp_path / "many.zip"
    make_zip(archive, [("a", b"1"), ("b", b"2"), ("c", b"3")])

    def forbidden_infolist(_self):
        raise AssertionError("infolist must not be called before ZIP preflight")

    monkeypatch.setattr(zipfile.ZipFile, "infolist", forbidden_infolist)
    with pytest.raises(ExtractionError, match="entry count"):
        safe_extract_archive(archive, tmp_path / "out", ExtractionLimits(max_files=1, max_directories=1))


def test_zip_central_directory_size_is_bounded(tmp_path):
    archive = tmp_path / "metadata.zip"
    make_zip(archive, [(f"entry-{i:03}.txt", b"x") for i in range(20)])
    with pytest.raises(ExtractionError, match="central-directory"):
        safe_extract_archive(archive, tmp_path / "out", ExtractionLimits(max_central_directory_bytes=64))


def test_rejects_case_collision_in_implicit_parent_directories(tmp_path):
    archive = tmp_path / "parent-case.zip"
    make_zip(archive, [("A/first.txt", b"1"), ("a/second.txt", b"2")])
    with pytest.raises(ExtractionError, match="case-colliding"):
        safe_extract_archive(archive, tmp_path / "out")


def test_explicit_directory_can_follow_implicit_directory(tmp_path):
    archive = tmp_path / "implicit-then-explicit.zip"
    make_zip(archive, [("etc/config", b"x"), ("etc/", b"")])
    out = tmp_path / "out"
    report = safe_extract_archive(archive, out)
    assert (out / "etc/config").read_bytes() == b"x"
    assert report["summary"]["directories"] == 1


def test_rejects_duplicate_explicit_directory(tmp_path):
    archive = tmp_path / "duplicate-dir.zip"
    with pytest.warns(UserWarning, match="Duplicate name"):
        make_zip(archive, [("etc/", b""), ("etc/", b"")])
    with pytest.raises(ExtractionError, match="duplicate"):
        safe_extract_archive(archive, tmp_path / "out")


def test_zip_unix_directory_mode_without_trailing_slash(tmp_path):
    archive = tmp_path / "mode-directory.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("etc")
        info.create_system = 3
        info.external_attr = (0o040755 << 16) | 0x10
        zf.writestr(info, b"")
        zf.writestr("etc/config", b"ok")
    out = tmp_path / "out"
    safe_extract_archive(archive, out)
    assert (out / "etc").is_dir()
    assert (out / "etc/config").read_bytes() == b"ok"


def test_rejects_conflicting_zip_directory_metadata(tmp_path):
    archive = tmp_path / "conflicting-mode.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("directory/")
        info.create_system = 3
        info.external_attr = 0o100644 << 16
        zf.writestr(info, b"")
    with pytest.raises(ExtractionError, match="conflicting ZIP directory"):
        safe_extract_archive(archive, tmp_path / "out")


def test_keyboard_interrupt_cleans_partial_extraction(tmp_path, monkeypatch):
    import fsa.extraction as extraction

    archive = tmp_path / "interrupt.zip"
    make_zip(archive, [("nested/file.txt", b"data")])
    out = tmp_path / "out"

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(extraction, "_copy_limited", interrupt)
    with pytest.raises(KeyboardInterrupt):
        safe_extract_archive(archive, out)
    assert not out.exists()


def test_keyboard_interrupt_preserves_preexisting_empty_destination(tmp_path, monkeypatch):
    import fsa.extraction as extraction

    archive = tmp_path / "interrupt-existing.zip"
    make_zip(archive, [("file.txt", b"data")])
    out = tmp_path / "out"
    out.mkdir()

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(extraction, "_copy_limited", interrupt)
    with pytest.raises(KeyboardInterrupt):
        safe_extract_archive(archive, out)
    assert out.is_dir()
    assert list(out.iterdir()) == []


def test_rejects_non_positive_time_budget():
    with pytest.raises(ValueError, match="max_seconds"):
        ExtractionLimits(max_seconds=0)
    with pytest.raises(ValueError, match="max_seconds"):
        ExtractionLimits(max_seconds=-1)


def test_zip_actual_central_directory_count_is_checked_before_infolist(tmp_path, monkeypatch):
    import struct

    archive = tmp_path / "forged-count.zip"
    make_zip(archive, [("a", b"1"), ("b", b"2"), ("c", b"3")])
    raw = bytearray(archive.read_bytes())
    eocd = raw.rfind(b"PK\x05\x06")
    # Forge both EOCD entry-count fields to under-report the real directory.
    struct.pack_into("<HH", raw, eocd + 8, 1, 1)
    archive.write_bytes(raw)

    def forbidden_infolist(_self):
        raise AssertionError("infolist must not run on a forged entry count")

    monkeypatch.setattr(zipfile.ZipFile, "infolist", forbidden_infolist)
    with pytest.raises(ExtractionError, match="entry count mismatch"):
        safe_extract_archive(archive, tmp_path / "out")


def test_parent_spelling_collision(tmp_path):
    archive = tmp_path / "names.zip"
    make_zip(archive, [("café/one", b"a"), ("cafe\u0301/two", b"b")])
    with pytest.raises(ExtractionError, match="colliding"):
        safe_extract_archive(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_normalized_report_matches_output(tmp_path):
    archive = tmp_path / "name.zip"
    make_zip(archive, [("cafe\u0301/one", b"a")])
    out = tmp_path / "out"
    report = safe_extract_archive(archive, out)
    assert report["entries"][0]["path"] == "café/one"
    assert (out / "café/one").read_bytes() == b"a"


def test_zip64_directory_with_small_payload(tmp_path, monkeypatch):
    archive = tmp_path / "small64.zip"
    monkeypatch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1)
    make_zip(archive, [("first", b"a"), ("second", b"b")])
    assert safe_extract_archive(archive, tmp_path / "out")["summary"]["files"] == 2


@pytest.mark.parametrize("kind", [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_tar_special_entry_policy(tmp_path, kind):
    archive = tmp_path / "sample.tar"
    with tarfile.open(archive, "w") as tf:
        entry = tarfile.TarInfo("special")
        entry.type = kind
        tf.addfile(entry)
    with pytest.raises(ExtractionError, match="special"):
        safe_extract_archive(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_pax_metadata_budget(tmp_path):
    archive = tmp_path / "sample.tar.gz"
    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("config")
        info.pax_headers = {"comment": "test note"}
        tf.addfile(info)
    out = tmp_path / "out"
    with pytest.raises(ExtractionError, match="metadata"):
        safe_extract_archive(archive, out, ExtractionLimits(max_tar_metadata_bytes=4))
    assert not out.exists()
    assert safe_extract_archive(archive, out)["summary"]["files"] == 1


def test_truncated_zip_preserves_empty_destination(tmp_path):
    archive = tmp_path / "cut.zip"
    make_zip(archive, [("readme", b"hello")])
    archive.write_bytes(archive.read_bytes()[:-18])
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ExtractionError):
        safe_extract_archive(archive, out)
    assert list(out.iterdir()) == []


def test_truncated_tar_header_rolls_back(tmp_path):
    archive = tmp_path / "short.tar"
    with tarfile.open(archive, "w") as tf:
        tf.addfile(tarfile.TarInfo("first"))
        tf.addfile(tarfile.TarInfo("second"))
    archive.write_bytes(archive.read_bytes()[:600])
    with pytest.raises(ExtractionError, match="header"):
        safe_extract_archive(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()
