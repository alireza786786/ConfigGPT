# -*- coding: utf-8 -*-
"""Phase 13 tests: atomic filesystem persistence (offline, tmp_path only).

Pins the writer contract: byte fidelity with Phase 12 (binary write, CRLF
untouched), atomicity (temp file + ``os.replace``; a failure leaves the
previous artifact and no debris), idempotence, containment (no traversal,
no absolute/drive paths, no symlink escape) and failure reporting that
never leaks content or credentials.
"""
import ast
import errno
import os
import pathlib
import threading
from dataclasses import replace

import pytest

import hubcore.writer as writer_mod
from hubcore import (
    DEFAULT_ENCODING,
    DEFAULT_ROOT,
    TEMP_FILE_PREFIX,
    TEMP_FILE_SUFFIX,
    CountryGroup,
    GeoInfo,
    LatencyKind,
    LatencySample,
    OutputBundle,
    OutputFile,
    OutputPolicy,
    UnsafeOutputPathError,
    WriteFailedError,
    WriteOutcome,
    WriterError,
    WriterPolicy,
    WrittenFile,
    build_outputs,
    parse_url,
    plan_outputs,
    score_node,
    validate_relative_path,
    write_bytes,
    write_outputs,
    write_text,
)

UUID = "11111111-2222-3333-4444-555555555555"
IP4 = "93.184.216.34"
OBSERVED_AT = 1_700_000_000.0
CRLF = "\r\n"


# ----------------------------------------------------------------------
# fixtures
# ----------------------------------------------------------------------
def build_node(path="/p1", ms=180.0, jitter=24.0, geo=None, host="a.com", port=443):
    n = parse_url(f"vless://{UUID}@{host}:{port}?security=tls&type=tcp&path={path}")
    n = replace(n, endpoint=replace(n.endpoint, resolved_ip=IP4))
    if ms is not None:
        n = n.with_measured(LatencySample(float(ms), LatencyKind.MEASURED,
                                          measured_at=OBSERVED_AT))
    if jitter is not None and ms is not None:
        n = n.with_jitter(float(jitter))
    if geo is not None:
        n = n.with_geo(geo)
    return n


def entry(n):
    return (n, score_node(n))


def canada():
    return GeoInfo(country="Canada", city="Vancouver", country_code="CA", flag="🇨🇦")


def germany():
    return GeoInfo(country="Germany", city="Berlin", country_code="DE", flag="🇩🇪")


def sample_bundle():
    """A bundle with several artifacts (protocols, transports, country, tiers)."""
    items = []
    # vless/tcp (scored) in Canada, within the ultra-fast tier
    items.append(entry(build_node(path="/fast", ms=120.0, jitter=10.0, geo=canada())))
    # vless/ws in Germany, over the ultra tier but under 500 ms
    ws = parse_url(f"vless://{UUID}@b.com:8443?security=tls&type=ws&path=/ws")
    ws = replace(ws, endpoint=replace(ws.endpoint, resolved_ip=IP4))
    ws = ws.with_measured(LatencySample(300.0, LatencyKind.MEASURED, measured_at=OBSERVED_AT))
    ws = ws.with_jitter(20.0)
    items.append(entry(ws.with_geo(germany())))
    return build_outputs(items)


def bundle_with(path=None, text=None, country_group=None):
    bundle = sample_bundle()
    if path is not None:
        return replace(bundle, by_protocol={path: text if text is not None else "x"})
    if country_group is not None:
        return replace(bundle, by_country=(country_group,))
    return bundle


def no_temp_files(root):
    return [p for p in pathlib.Path(root).rglob("*")
            if p.name.startswith(TEMP_FILE_PREFIX) or p.name.endswith(TEMP_FILE_SUFFIX)]


def read_bytes(root, relpath):
    return (pathlib.Path(root) / relpath).read_bytes()


# ==========================================================================
# path validation
# ==========================================================================
class TestValidateRelativePath:
    @pytest.mark.parametrize("good", [
        "all.txt", "all_b64.txt", "Config/vless.txt", "transports/ws.txt",
        "Country/آلمان.txt", "Subscription/ultra_fast.txt", "a/b/c.txt",
        "Country/United_States.txt", "file with spaces.txt",
    ])
    def test_accepted_paths_are_canonical(self, good):
        assert validate_relative_path(good) == good

    @pytest.mark.parametrize("bad", [
        "", "/etc/passwd", "//server/share/x", "C:/x", "C:x", "C:\\x",
        "../x", "a/../../x", "a//b", "a/./b", ".", "..", "a/..", "x\x00y",
        "Config/x:y.txt", "Config\\..\\evil.txt", "..\\x", "x" * 600,
        # reserved device names (B5) and trailing dot/space aliases (B4a)
        "NUL", "Country/NUL.txt", "con.txt", "Config/COM1.txt",
        "Country/lpt9.txt", "out/PRN", "Country/Canada.txt.", "file. ",
    ])
    def test_dangerous_paths_are_refused(self, bad):
        with pytest.raises(UnsafeOutputPathError):
            validate_relative_path(bad)

    @pytest.mark.parametrize("bad", [None, 5, b"a.txt", ["a.txt"]])
    def test_non_text_paths_are_refused(self, bad):
        with pytest.raises(UnsafeOutputPathError):
            validate_relative_path(bad)

    def test_backslashes_are_normalised_to_posix(self):
        assert validate_relative_path("Config\\vless.txt") == "Config/vless.txt"


# ==========================================================================
# planning
# ==========================================================================
class TestPlanOutputs:
    def test_paths_are_the_legacy_artifacts(self):
        files = plan_outputs(sample_bundle())
        paths = [f.path for f in files]
        assert paths == [
            "all.txt", "all_b64.txt",
            "Config/vless.txt", "transports/tcp.txt", "transports/ws.txt",
            "Country/Canada.txt", "Country/Germany.txt",
            "Subscription/ultra_fast.txt", "Subscription/good_ping.txt",
        ]

    def test_kinds_are_labelled(self):
        kinds = {f.path: f.kind for f in plan_outputs(sample_bundle())}
        assert kinds["all.txt"] == "all"
        assert kinds["all_b64.txt"] == "all_base64"
        assert kinds["Config/vless.txt"] == "protocol"
        assert kinds["transports/tcp.txt"] == "transport"
        assert kinds["Country/Canada.txt"] == "country"
        assert kinds["Subscription/ultra_fast.txt"] == "tier"

    def test_planning_is_pure_and_deterministic(self):
        bundle = sample_bundle()
        first = plan_outputs(bundle)
        second = plan_outputs(bundle)
        assert [f.path for f in first] == [f.path for f in second]
        assert [f.text for f in first] == [f.text for f in second]

    def test_planned_text_is_the_bundle_text_verbatim(self):
        bundle = sample_bundle()
        by_path = {f.path: f.text for f in plan_outputs(bundle)}
        assert by_path["all.txt"] == bundle.all_text
        assert by_path["all_b64.txt"] == bundle.all_base64
        assert by_path["Config/vless.txt"] == bundle.by_protocol["Config/vless.txt"]
        assert by_path["Country/Canada.txt"] == \
            next(g.text for g in bundle.by_country if g.filename == "Canada")

    def test_non_bundle_input_is_refused(self):
        for bad in (None, 42, "bundle", {"all.txt": "x"}):
            with pytest.raises(WriterError):
                plan_outputs(bad)

    def test_duplicate_paths_are_refused(self):
        bundle = sample_bundle()
        clash = replace(bundle, by_transport={"Config/vless.txt": "clash"})
        with pytest.raises(WriterError):
            plan_outputs(clash)

    def test_hostile_protocol_path_is_refused_before_any_write(self, tmp_path):
        bundle = bundle_with(path="../../../evil.txt")
        with pytest.raises(UnsafeOutputPathError):
            plan_outputs(bundle)
        with pytest.raises(UnsafeOutputPathError):
            write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        assert not (tmp_path.parent / "evil.txt").exists()

    def test_hostile_country_path_is_refused(self, tmp_path):
        group = CountryGroup(filename="x", path="../../outside.txt",
                             country="X", flag="🌐", count=1, text="x\r\n")
        with pytest.raises(UnsafeOutputPathError):
            write_outputs(bundle_with(country_group=group),
                          WriterPolicy(root=str(tmp_path)))
        assert not (tmp_path.parent / "outside.txt").exists()

    def test_absolute_path_in_a_bundle_is_refused(self, tmp_path):
        bundle = bundle_with(path="/tmp/absolute.txt", text="x")
        with pytest.raises(UnsafeOutputPathError):
            write_outputs(bundle, WriterPolicy(root=str(tmp_path)))

    def test_non_text_artifact_is_refused(self):
        bundle = replace(sample_bundle(), all_text=b"bytes")
        with pytest.raises(WriterError):
            plan_outputs(bundle)


# ==========================================================================
# single-artifact writes
# ==========================================================================
class TestSingleArtifact:
    def test_write_text_preserves_crlf_bytes(self, tmp_path):
        policy = WriterPolicy(root=str(tmp_path))
        result = write_text(policy, "a.txt", "one\r\ntwo\r\n")
        assert result == WrittenFile(path="a.txt", size=10, changed=True)
        assert read_bytes(tmp_path, "a.txt") == b"one\r\ntwo\r\n"
        assert b"\r\r" not in read_bytes(tmp_path, "a.txt")

    def test_write_bytes_is_raw(self, tmp_path):
        write_bytes(WriterPolicy(root=str(tmp_path)), "raw.bin", b"\x00\x01\r\n")
        assert read_bytes(tmp_path, "raw.bin") == b"\x00\x01\r\n"

    def test_default_policy_root_and_encoding(self):
        policy = WriterPolicy()
        assert policy.root == DEFAULT_ROOT == "."
        assert policy.encoding == DEFAULT_ENCODING == "utf-8"

    def test_invalid_policy_is_refused(self, tmp_path):
        with pytest.raises(WriterError):
            write_text({"root": str(tmp_path)}, "a.txt", "x")
        with pytest.raises(WriterError):
            write_text(WriterPolicy(root=""), "a.txt", "x")
        with pytest.raises(WriterError):
            write_text(WriterPolicy(root=str(tmp_path), encoding="not-a-codec"),
                       "a.txt", "x")

    def test_non_str_text_and_non_bytes_data_are_refused(self, tmp_path):
        policy = WriterPolicy(root=str(tmp_path))
        with pytest.raises(WriterError):
            write_text(policy, "a.txt", b"bytes")
        with pytest.raises(WriterError):
            write_bytes(policy, "a.txt", "text")

    def test_parent_directories_are_created(self, tmp_path):
        write_text(WriterPolicy(root=str(tmp_path)), "x/y/z.txt", "v")
        assert (tmp_path / "x" / "y" / "z.txt").is_file()

    def test_root_is_created_when_missing(self, tmp_path):
        root = tmp_path / "new" / "root"
        write_text(WriterPolicy(root=str(root)), "a.txt", "v")
        assert (root / "a.txt").read_text(encoding="utf-8") == "v"

    def test_create_root_false_on_missing_root_fails_cleanly(self, tmp_path):
        root = tmp_path / "absent"
        with pytest.raises(WriteFailedError) as exc:
            write_text(WriterPolicy(root=str(root), create_root=False), "a.txt", "v")
        assert exc.value.reason == "missing_directory"
        assert not root.exists()


# ==========================================================================
# bundle writes: byte identity with Phase 12
# ==========================================================================
class TestBundleByteIdentity:
    def test_every_artifact_is_byte_identical_to_phase12(self, tmp_path):
        bundle = sample_bundle()
        outcome = write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        for planned in plan_outputs(bundle):
            assert read_bytes(tmp_path, planned.path) == planned.text.encode("utf-8")
        assert outcome.total == len(plan_outputs(bundle))

    def test_crlf_is_untouched_by_the_write(self, tmp_path):
        bundle = sample_bundle()
        write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        raw = read_bytes(tmp_path, "all.txt")
        assert raw.count(b"\r\n") == 2
        assert b"\r\r" not in raw and raw.replace(b"\r\n", b"").count(b"\n") == 0
        assert raw.endswith(b"\r\n")

    def test_base64_artifact_has_no_line_breaks(self, tmp_path):
        bundle = sample_bundle()
        write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        raw = read_bytes(tmp_path, "all_b64.txt")
        assert b"\n" not in raw and b"\r" not in raw
        assert raw == bundle.all_base64.encode("ascii")

    def test_empty_bundle_artifacts(self, tmp_path):
        bundle = build_outputs([])
        write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        assert read_bytes(tmp_path, "all.txt") == b"\r\n"
        assert read_bytes(tmp_path, "all_b64.txt") == b""
        assert read_bytes(tmp_path, "Subscription/ultra_fast.txt") == b"\r\n"
        assert read_bytes(tmp_path, "Subscription/good_ping.txt") == b"\r\n"
        assert not (tmp_path / "Config").exists()

    def test_unicode_country_filename_and_content(self, tmp_path):
        items = [entry(build_node(geo=GeoInfo(country="آلمان", city="برلین",
                                              country_code="DE", flag="🇩🇪")))]
        bundle = build_outputs(items)
        write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        assert (tmp_path / "Country" / "آلمان.txt").is_file()
        raw = read_bytes(tmp_path, "Country/آلمان.txt")
        assert raw.endswith(b"\r\n") and b"\n" not in raw[:-2]
        # the brand name lives in the percent-encoded fragment (Phase 12
        # contract), so unquote before looking for the unicode text
        from urllib.parse import unquote
        line = raw.decode("utf-8").rstrip("\r\n")
        assert "برلین" in unquote(line.split("#", 1)[1])

    def test_directories_match_the_legacy_layout(self, tmp_path):
        write_outputs(sample_bundle(), WriterPolicy(root=str(tmp_path)))
        for directory in ("Config", "transports", "Country", "Subscription"):
            assert (tmp_path / directory).is_dir()

    def test_outcome_reporting(self, tmp_path):
        outcome = write_outputs(sample_bundle(), WriterPolicy(root=str(tmp_path)))
        assert isinstance(outcome, WriteOutcome)
        assert outcome.written == outcome.total == 9
        assert outcome.unchanged == 0
        assert outcome.bytes_written == sum(
            len(f.text.encode("utf-8")) for f in plan_outputs(sample_bundle()))
        assert outcome.paths[0] == "all.txt"
        assert outcome.root == str(tmp_path)

    def test_no_temporary_files_are_left_behind(self, tmp_path):
        write_outputs(sample_bundle(), WriterPolicy(root=str(tmp_path)))
        assert no_temp_files(tmp_path) == []

    def test_existing_unrelated_files_are_not_touched(self, tmp_path):
        keep = tmp_path / "README.md"
        keep.write_bytes(b"keep me\r\n")
        write_outputs(sample_bundle(), WriterPolicy(root=str(tmp_path)))
        assert keep.read_bytes() == b"keep me\r\n"

    def test_stale_artifacts_are_not_pruned(self, tmp_path):
        policy = WriterPolicy(root=str(tmp_path))
        write_outputs(build_outputs([entry(build_node(geo=canada()))]), policy)
        assert (tmp_path / "Country" / "Canada.txt").is_file()
        write_outputs(build_outputs([entry(build_node(path="/g", geo=germany()))]), policy)
        assert (tmp_path / "Country" / "Canada.txt").is_file()   # not pruned


# ==========================================================================
# idempotence
# ==========================================================================
class TestIdempotence:
    def test_second_run_is_a_no_op(self, tmp_path):
        bundle = sample_bundle()
        policy = WriterPolicy(root=str(tmp_path))
        first = write_outputs(bundle, policy)
        before = {f.path: read_bytes(tmp_path, f.path) for f in first.files}
        second = write_outputs(bundle, policy)
        assert first.written == 9 and second.written == 0
        assert second.unchanged == 9 and second.bytes_written == 0
        assert {f.path: read_bytes(tmp_path, f.path) for f in second.files} == before
        assert no_temp_files(tmp_path) == []

    def test_changed_bundle_rewrites_only_the_changed_artifacts(self, tmp_path):
        policy = WriterPolicy(root=str(tmp_path))
        write_outputs(sample_bundle(), policy)
        changed = replace(sample_bundle(), all_text="vless://new\r\n")
        outcome = write_outputs(changed, policy)
        assert outcome.written == 1 and outcome.unchanged == 8
        assert read_bytes(tmp_path, "all.txt") == b"vless://new\r\n"

    def test_skip_identical_false_rewrites_the_same_bytes(self, tmp_path):
        bundle = sample_bundle()
        policy = WriterPolicy(root=str(tmp_path), skip_identical=False)
        write_outputs(bundle, policy)
        second = write_outputs(bundle, policy)
        assert second.written == 9 and second.unchanged == 0
        assert read_bytes(tmp_path, "all.txt") == bundle.all_text.encode("utf-8")

    def test_externally_tampered_artifact_is_restored(self, tmp_path):
        bundle = sample_bundle()
        policy = WriterPolicy(root=str(tmp_path))
        write_outputs(bundle, policy)
        (tmp_path / "all.txt").write_bytes(b"tampered\r\n")
        outcome = write_outputs(bundle, policy)
        assert outcome.written == 1
        assert read_bytes(tmp_path, "all.txt") == bundle.all_text.encode("utf-8")

    def test_repeated_runs_never_leave_debris(self, tmp_path):
        policy = WriterPolicy(root=str(tmp_path))
        for _ in range(3):
            write_outputs(sample_bundle(), policy)
        assert no_temp_files(tmp_path) == []


# ==========================================================================
# atomicity
# ==========================================================================
class TestAtomicity:
    def test_write_goes_through_a_temporary_file_and_replace(self, tmp_path, monkeypatch):
        seen = {}
        real_replace = os.replace

        def spy(src, dst):
            seen["src"] = str(src)
            seen["dst"] = str(dst)
            return real_replace(src, dst)

        monkeypatch.setattr(writer_mod.os, "replace", spy)
        write_text(WriterPolicy(root=str(tmp_path)), "a.txt", "v\r\n")
        assert TEMP_FILE_PREFIX in os.path.basename(seen["src"])
        assert seen["dst"] == str(tmp_path / "a.txt")
        assert not os.path.exists(seen["src"])
        assert read_bytes(tmp_path, "a.txt") == b"v\r\n"

    def test_failure_during_write_leaves_no_target_and_no_debris(self, tmp_path, monkeypatch):
        def boom(*args, **kwargs):
            raise OSError(errno.EIO, "simulated device failure")

        monkeypatch.setattr(writer_mod.os, "fsync", boom)
        with pytest.raises(WriteFailedError) as exc:
            write_text(WriterPolicy(root=str(tmp_path)), "a.txt", "payload\r\n")
        assert exc.value.reason == "io_error" and exc.value.operation == "write"
        assert not (tmp_path / "a.txt").exists()
        assert no_temp_files(tmp_path) == []

    def test_failure_during_replace_preserves_the_previous_content(self, tmp_path, monkeypatch):
        target = tmp_path / "a.txt"
        target.write_bytes(b"previous\r\n")
        monkeypatch.setattr(writer_mod.os, "replace",
                            lambda *a, **k: (_ for _ in ()).throw(PermissionError("nope")))
        with pytest.raises(WriteFailedError) as exc:
            write_text(WriterPolicy(root=str(tmp_path)), "a.txt", "new\r\n")
        assert exc.value.reason == "permission_denied" and exc.value.operation == "replace"
        assert target.read_bytes() == b"previous\r\n"      # never half-written
        assert no_temp_files(tmp_path) == []

    def test_partial_bundle_failure_keeps_later_artifacts_intact(self, tmp_path, monkeypatch):
        bundle = sample_bundle()
        # skip_identical=False so every artifact hits os.replace in plan
        # order and the third failure is deterministic
        policy = WriterPolicy(root=str(tmp_path), skip_identical=False)
        first = write_outputs(bundle, policy)
        assert first.written == 9
        paths = [f.path for f in first.files]
        before = {p: read_bytes(tmp_path, p) for p in paths}

        calls = {"n": 0}
        real_replace = os.replace

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 3:                     # fail on the 3rd artifact
                raise OSError(errno.ENOSPC, "disk full")
            return real_replace(src, dst)

        monkeypatch.setattr(writer_mod.os, "replace", flaky)
        changed = replace(bundle, all_text="different\r\n")
        with pytest.raises(WriteFailedError) as exc:
            write_outputs(changed, policy)
        assert exc.value.reason == "no_space" and exc.value.path == paths[2]
        # artifact 1 was replaced before the failure, artifact 3 failed
        # atomically, and 3..n keep their previous bytes untouched
        assert read_bytes(tmp_path, paths[0]) == changed.all_text.encode("utf-8")
        for path in paths[2:]:
            assert read_bytes(tmp_path, path) == before[path]
        assert no_temp_files(tmp_path) == []

    def test_failure_while_creating_a_directory_is_reported(self, tmp_path, monkeypatch):
        def boom(*args, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr(writer_mod.os, "makedirs", boom)
        with pytest.raises(WriteFailedError) as exc:
            write_text(WriterPolicy(root=str(tmp_path)), "Config/a.txt", "v")
        assert exc.value.reason == "permission_denied"
        assert exc.value.operation == "create directory"
        assert no_temp_files(tmp_path) == []

    def test_file_where_a_directory_belongs_is_reported(self, tmp_path):
        (tmp_path / "Config").write_bytes(b"i am a file")
        with pytest.raises(WriteFailedError) as exc:
            write_text(WriterPolicy(root=str(tmp_path)), "Config/a.txt", "v")
        assert exc.value.reason in ("path_is_a_file", "not_a_directory", "io_error")
        assert (tmp_path / "Config").read_bytes() == b"i am a file"
        assert no_temp_files(tmp_path) == []


# ==========================================================================
# concurrency
# ==========================================================================
class TestConcurrency:
    def test_parallel_writers_of_the_same_bundle_agree(self, tmp_path):
        bundle = sample_bundle()
        policy = WriterPolicy(root=str(tmp_path))
        errors = []
        barrier = threading.Barrier(8)

        def run():
            try:
                barrier.wait(timeout=10)
                write_outputs(bundle, policy)
            except Exception as exc:                     # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=run) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert errors == []
        assert read_bytes(tmp_path, "all.txt") == bundle.all_text.encode("utf-8")
        assert no_temp_files(tmp_path) == []

    def test_parallel_writers_of_different_bundles_never_interleave(self, tmp_path):
        first = replace(build_outputs([]), all_text="a" * 5000 + CRLF)
        second = replace(build_outputs([]), all_text="b" * 5000 + CRLF)
        policy = WriterPolicy(root=str(tmp_path))
        barrier = threading.Barrier(2)
        errors = []

        def run(bundle):
            try:
                barrier.wait(timeout=10)
                for _ in range(5):
                    write_outputs(bundle, policy)
            except Exception as exc:                     # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=run, args=(b,)) for b in (first, second)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert errors == []
        final = read_bytes(tmp_path, "all.txt")
        assert final in (first.all_text.encode("utf-8"), second.all_text.encode("utf-8"))
        assert no_temp_files(tmp_path) == []


# ==========================================================================
# containment / symlink escape
# ==========================================================================
class TestContainment:
    def _link_or_skip(self, target, link, directory=False):
        """Link ``link`` to ``target``, or skip if the host forbids it.

        A real symlink needs a privilege on Windows, but a DIRECTORY
        junction does not, so directory-escape coverage still runs here.
        """
        try:
            os.symlink(str(target), str(link))
            return "symlink"
        except (OSError, NotImplementedError) as exc:
            if not directory or os.name != "nt":
                pytest.skip(f"symlinks unavailable here: {exc}")
        import shutil
        import subprocess
        if not shutil.which("cmd"):
            pytest.skip("no cmd.exe available to create a junction")
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                                capture_output=True, text=True)
        if result.returncode != 0:
            pytest.skip(f"junction unavailable: {(result.stdout or result.stderr).strip()}")
        return "junction"

    def test_symlinked_directory_escaping_the_root_is_refused(self, tmp_path):
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        self._link_or_skip(outside, root / "escape", directory=True)
        with pytest.raises(UnsafeOutputPathError):
            write_text(WriterPolicy(root=str(root)), "escape/evil.txt", "x")
        assert not (outside / "evil.txt").exists()
        assert no_temp_files(tmp_path) == []

    def test_nested_directory_escape_is_refused(self, tmp_path):
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        (root / "Config").mkdir(parents=True)
        outside.mkdir()
        self._link_or_skip(outside, root / "Config" / "deep", directory=True)
        with pytest.raises(UnsafeOutputPathError):
            write_text(WriterPolicy(root=str(root)), "Config/deep/x.txt", "x")
        assert not (outside / "x.txt").exists()
        assert no_temp_files(tmp_path) == []

    def test_destination_symlink_is_refused(self, tmp_path):
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        victim = outside / "victim.txt"
        victim.write_bytes(b"original\r\n")
        self._link_or_skip(victim, root / "link.txt")
        with pytest.raises(UnsafeOutputPathError):
            write_text(WriterPolicy(root=str(root)), "link.txt", "overwritten\r\n")
        assert victim.read_bytes() == b"original\r\n"

    def test_in_root_symlinked_directory_is_accepted_for_a_real_path(self, tmp_path):
        root = tmp_path / "root"
        real = root / "real"
        real.mkdir(parents=True)
        self._link_or_skip(real, root / "alias", directory=True)
        # alias resolves INSIDE the root, so containment holds
        write_text(WriterPolicy(root=str(root)), "alias/a.txt", "v\r\n")
        assert (real / "a.txt").read_bytes() == b"v\r\n"

    def test_relative_root_is_resolved_against_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        write_text(WriterPolicy(root="out"), "a.txt", "v")
        assert (tmp_path / "out" / "a.txt").read_bytes() == b"v"


# ==========================================================================
# link / interrupt / filesystem-shape safety (hunt-found defects)
# ==========================================================================
class TestLinkAndInterruptSafety:
    def test_hard_link_cannot_redirect_a_write_outside_the_root(self, tmp_path):
        # a hard link is not a symlink, so it is not refused - but the
        # temp-file + replace strategy must break the link instead of
        # writing through it into a file outside the root
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"ORIGINAL\r\n")
        os.link(str(outside), str(root / "link.txt"))
        write_text(WriterPolicy(root=str(root)), "link.txt", "NEW\r\n")
        assert outside.read_bytes() == b"ORIGINAL\r\n"
        assert (root / "link.txt").read_bytes() == b"NEW\r\n"

    def test_unsafe_target_kinds_fail_typed_and_leave_no_debris(self, tmp_path):
        # B6-adjacent: every odd filesystem shape must fail as a typed
        # error, never with a traceback from the standard library
        (tmp_path / "as_file").write_bytes(b"x")
        (tmp_path / "target_dir").mkdir()
        (tmp_path / "target_dir" / "all.txt").mkdir()
        with pytest.raises(WriteFailedError) as root_exc:
            write_text(WriterPolicy(root=str(tmp_path / "as_file")), "a.txt", "v")
        assert root_exc.value.reason == "path_is_a_file"
        with pytest.raises(WriteFailedError) as parent_exc:
            write_text(WriterPolicy(root=str(tmp_path / "target_dir")), "all.txt", "v")
        assert parent_exc.value.operation == "replace"
        assert (tmp_path / "as_file").read_bytes() == b"x"
        assert (tmp_path / "target_dir" / "all.txt").is_dir()
        assert no_temp_files(tmp_path) == []

    def test_a_parent_segment_that_is_a_file_fails_typed(self, tmp_path):
        (tmp_path / "Config").write_bytes(b"x")
        with pytest.raises(WriteFailedError) as exc:
            write_text(WriterPolicy(root=str(tmp_path)), "Config/vless.txt", "v")
        assert exc.value.reason == "path_is_a_file"
        assert (tmp_path / "Config").read_bytes() == b"x"
        assert no_temp_files(tmp_path) == []

    @pytest.mark.parametrize("operation", ["fsync", "replace", "fdopen"])
    def test_interrupt_leaves_the_old_bytes_and_no_debris(self, tmp_path, monkeypatch, operation):
        # B6: an interrupt in the mkstemp -> fdopen window used to leak the
        # raw descriptor, and Windows cannot unlink an open file, so a
        # .hubcore-tmp-*.part was left next to the artifacts
        root = tmp_path / "out"
        write_text(WriterPolicy(root=str(root)), "all.txt", "OLD\r\n")
        def boom(*args, **kwargs):
            raise KeyboardInterrupt()
        monkeypatch.setattr(writer_mod.os, operation, boom)
        with pytest.raises(KeyboardInterrupt):
            write_text(WriterPolicy(root=str(root)), "all.txt", "NEW\r\n")
        monkeypatch.undo()
        assert (root / "all.txt").read_bytes() == b"OLD\r\n"
        assert no_temp_files(tmp_path) == []

    def test_interrupt_does_not_swallow_the_original_error_type(self, tmp_path, monkeypatch):
        # a Ctrl+C must never be converted into a WriteFailedError
        root = tmp_path / "out"
        monkeypatch.setattr(writer_mod.os, "replace",
                            lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
        with pytest.raises(KeyboardInterrupt):
            write_text(WriterPolicy(root=str(root)), "all.txt", "v")

    def test_two_spellings_of_one_path_are_refused(self, tmp_path):
        backslash = chr(92)
        bundle = replace(sample_bundle(), by_protocol={
            "Config/vless.txt": "A", "Config" + backslash + "vless.txt": "B"})
        with pytest.raises(WriterError):
            write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        assert list(pathlib.Path(tmp_path).rglob("*")) == []

    def test_non_ascii_output_root_is_supported(self, tmp_path):
        root = tmp_path / "پوشه خروجی آلمان"
        write_text(WriterPolicy(root=str(root)), "Country/آلمان.txt", "سلام\r\n")
        assert (root / "Country" / "آلمان.txt").read_bytes() == "سلام\r\n".encode("utf-8")

    def test_deep_new_directories_are_created(self, tmp_path):
        write_text(WriterPolicy(root=str(tmp_path)), "a/b/c/d.txt", "v")
        assert (tmp_path / "a" / "b" / "c" / "d.txt").read_bytes() == b"v"


# ==========================================================================
# path aliasing (hunt-found defects)
# ==========================================================================
class TestPathAliasing:
    """B4/B4a/B5: paths that would alias ONE file must be refused up front."""

    def test_case_only_collision_is_refused(self, tmp_path):
        # B4: on a case-insensitive filesystem both paths name ONE file, so
        # the second artifact silently replaced the first while the outcome
        # still counted every artifact as written
        bundle = replace(sample_bundle(),
                         by_protocol={"Config/vless.txt": "AAA\r\n",
                                      "Config/VLESS.txt": "BBB\r\n"})
        with pytest.raises(WriterError) as exc:
            write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        assert "case" in str(exc.value)
        assert "AAA" not in str(exc.value) and "BBB" not in str(exc.value)
        assert list(pathlib.Path(tmp_path).rglob("*")) == []

    def test_case_only_collision_is_refused_at_plan_time(self):
        bundle = replace(sample_bundle(),
                         by_protocol={"Config/vless.txt": "A",
                                      "Config/VLESS.txt": "B"})
        with pytest.raises(WriterError):
            plan_outputs(bundle)

    def test_isolated_case_differences_are_still_fine(self):
        # only a COLLISION is refused; a single mixed-case path is not
        bundle = replace(sample_bundle(), by_protocol={"Config/VLESS.txt": "A"})
        assert [f.path for f in plan_outputs(bundle)] == [
            "all.txt", "all_b64.txt", "Config/VLESS.txt",
            "transports/tcp.txt", "transports/ws.txt",
            "Country/Canada.txt", "Country/Germany.txt",
            "Subscription/ultra_fast.txt", "Subscription/good_ping.txt",
        ]

    def test_reserved_device_name_is_refused_before_any_io(self, tmp_path):
        # B5: "Country/NUL.txt" still names the NUL device on Windows; the
        # old code only failed at replace time, with the misleading reason
        # "path_is_a_file", and a device write can discard data silently
        with pytest.raises(UnsafeOutputPathError):
            write_text(WriterPolicy(root=str(tmp_path)), "Country/NUL.txt", "x")
        assert list(pathlib.Path(tmp_path).rglob("*")) == []

    def test_bundle_with_a_reserved_device_name_is_refused(self, tmp_path):
        bundle = replace(sample_bundle(), by_protocol={"Config/NUL.txt": "x"})
        with pytest.raises(UnsafeOutputPathError):
            write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        assert list(pathlib.Path(tmp_path).rglob("*")) == []

    def test_names_that_merely_contain_a_reserved_word_are_allowed(self, tmp_path):
        write_text(WriterPolicy(root=str(tmp_path)), "Country/connection.txt", "v")
        assert (tmp_path / "Country" / "connection.txt").read_bytes() == b"v"

    @pytest.mark.parametrize("alias", ["Country/Canada.txt.", "file. ", "a "
                                       ])
    def test_trailing_dot_or_space_alias_is_refused(self, alias):
        # B4a: Windows strips trailing dots/spaces, so "a.txt." == "a.txt"
        with pytest.raises(UnsafeOutputPathError):
            validate_relative_path(alias)

    def test_trailing_dot_alias_cannot_reach_the_filesystem(self, tmp_path):
        bundle = replace(sample_bundle(), by_protocol={
            "Country/Canada.txt": "A\r\n", "Country/Canada.txt.": "B\r\n"})
        with pytest.raises(UnsafeOutputPathError):
            write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        assert list(pathlib.Path(tmp_path).rglob("*")) == []


# ==========================================================================
# encoding policy (UTF-8 only, per the Phase 12 contract)
# ==========================================================================
class TestEncodingPolicy:
    @pytest.mark.parametrize("enc", ["utf-16", "latin-1", "cp1252", "ascii"])
    def test_non_utf8_encodings_are_refused(self, tmp_path, enc):
        with pytest.raises(WriterError):
            write_text(WriterPolicy(root=str(tmp_path), encoding=enc), "a.txt", "v")
        assert list(pathlib.Path(tmp_path).rglob("*")) == []

    @pytest.mark.parametrize("enc", ["UTF-8", "utf8", "utf_8"])
    def test_utf8_aliases_are_accepted(self, tmp_path, enc):
        write_text(WriterPolicy(root=str(tmp_path), encoding=enc), "a.txt", "v")
        assert (tmp_path / "a.txt").read_bytes() == b"v"

    def test_non_text_encoding_is_refused(self, tmp_path):
        with pytest.raises(WriterError):
            write_text(WriterPolicy(root=str(tmp_path), encoding=None), "a.txt", "v")


# ==========================================================================
# failure reporting / secret safety
# ==========================================================================
class TestFailureReporting:
    def test_temporary_file_creation_failure_is_reported(self, tmp_path, monkeypatch):
        def boom(*args, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr(writer_mod.tempfile, "mkstemp", boom)
        with pytest.raises(WriteFailedError) as exc:
            write_text(WriterPolicy(root=str(tmp_path)), "a.txt", "v")
        assert exc.value.reason == "permission_denied"
        assert exc.value.operation == "create temporary file"
        assert str(exc.value.path) == "a.txt"
        assert no_temp_files(tmp_path) == []

    def test_disk_full_is_mapped(self, tmp_path, monkeypatch):
        def boom(*args, **kwargs):
            raise OSError(errno.ENOSPC, "disk full")

        monkeypatch.setattr(writer_mod.tempfile, "mkstemp", boom)
        with pytest.raises(WriteFailedError) as exc:
            write_text(WriterPolicy(root=str(tmp_path)), "a.txt", "v")
        assert exc.value.reason == "no_space"

    def test_read_only_filesystem_is_mapped(self, tmp_path, monkeypatch):
        def boom(*args, **kwargs):
            raise OSError(errno.EROFS, "read only")

        monkeypatch.setattr(writer_mod.tempfile, "mkstemp", boom)
        with pytest.raises(WriteFailedError) as exc:
            write_text(WriterPolicy(root=str(tmp_path)), "a.txt", "v")
        assert exc.value.reason == "read_only_filesystem"

    def test_errors_are_value_errors(self):
        for exc in (WriterError, UnsafeOutputPathError, WriteFailedError):
            assert issubclass(exc, ValueError)

    def test_error_messages_never_leak_content_or_credentials(self, tmp_path):
        secret = "SUPERSECRETPASSWORD"
        node = parse_url(f"trojan://{secret}@t.com:443?security=tls&type=tcp")
        node = replace(node, endpoint=replace(node.endpoint, resolved_ip=IP4))
        bundle = build_outputs([(node, score_node(node))])
        assert secret in bundle.all_text            # the config link is the payload

        def boom(src, dst):
            raise PermissionError("denied")

        import unittest.mock as mock
        with mock.patch.object(writer_mod.os, "replace", boom):
            with pytest.raises(WriteFailedError) as exc:
                write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        message = str(exc.value)
        assert secret not in message
        assert UUID not in message and "trojan" not in message
        assert "://" not in message
        assert no_temp_files(tmp_path) == []

    def test_no_partial_file_contains_the_payload_after_a_failure(self, tmp_path, monkeypatch):
        secret = "SUPERSECRETPASSWORD"
        node = parse_url(f"trojan://{secret}@t.com:443?security=tls&type=tcp")
        node = replace(node, endpoint=replace(node.endpoint, resolved_ip=IP4))
        bundle = build_outputs([(node, score_node(node))])
        monkeypatch.setattr(writer_mod.os, "fsync",
                            lambda *a, **k: (_ for _ in ()).throw(OSError(errno.EIO, "x")))
        with pytest.raises(WriteFailedError):
            write_outputs(bundle, WriterPolicy(root=str(tmp_path)))
        leftovers = [p for p in pathlib.Path(tmp_path).rglob("*") if p.is_file()]
        assert leftovers == []
        for path in leftovers:
            assert secret.encode() not in path.read_bytes()


# ==========================================================================
# purity
# ==========================================================================
ALLOWED_MODULES = {
    "__future__", "codecs", "errno", "ntpath", "os", "tempfile", "threading",
    "dataclasses", "pathlib", "typing", "hubcore.output",
}
BANNED_TOKENS = (
    "socket", "subprocess", "urllib", "http.client", "requests", "telegram",
    "shutil", "eval(", "exec(", "os.system", "os.environ", "curl",
    "import time", "from time", "datetime", "monotonic", "random",
)
BANNED_CALLS = {
    "system", "popen", "eval", "exec", "compile", "spawn", "fork", "execv",
    "urlopen", "socket", "getenv", "gethostbyname", "getaddrinfo",
    "create_connection", "mkdirs", "rmtree", "removedirs", "rename",
}
BANNED_ATTRS = {"environ", "system", "popen", "spawn"}


def writer_source():
    return pathlib.Path(writer_mod.__file__).read_text(encoding="utf-8")


def called_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


class TestPurity:
    def test_imports_are_whitelisted(self):
        tree = ast.parse(writer_source())
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.add(node.module or "")
        assert modules <= ALLOWED_MODULES, modules - ALLOWED_MODULES

    def test_no_banned_source_tokens(self):
        src = writer_source()
        for token in BANNED_TOKENS:
            assert token not in src, f"writer must not reference {token}"

    def test_no_banned_calls_or_attributes(self):
        tree = ast.parse(writer_source())
        assert not (called_names(tree) & BANNED_CALLS), called_names(tree) & BANNED_CALLS
        attrs = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        assert not (attrs & BANNED_ATTRS), attrs & BANNED_ATTRS

    def test_no_network_or_process_objects_are_reachable(self):
        for name in ("socket", "subprocess", "requests", "urllib", "http",
                     "shutil", "telegram", "time", "random", "sys"):
            assert not hasattr(writer_mod, name), name

    def test_writer_performs_no_network_calls(self, tmp_path):
        # a bundle whose country name looks like a URL/host must never
        # trigger resolution: only sanitised filenames are touched
        items = [entry(build_node(geo=GeoInfo(country="http://evil.example.com",
                                              city="c", country_code="XX", flag="🌐")))]
        outcome = write_outputs(build_outputs(items), WriterPolicy(root=str(tmp_path)))
        assert all(":" not in f.path for f in outcome.files)


# ==========================================================================
# performance
# ==========================================================================
class TestPerformance:
    def test_a_few_thousand_nodes_persist_quickly(self, tmp_path):
        import time as _time
        items = [entry(build_node(path=f"/p{i}", ms=100.0 + (i % 400),
                                  geo=canada() if i % 2 else germany()))
                 for i in range(2000)]
        bundle = build_outputs(items)
        policy = WriterPolicy(root=str(tmp_path))
        t0 = _time.monotonic()
        outcome = write_outputs(bundle, policy)
        dt = _time.monotonic() - t0
        assert outcome.written == outcome.total
        assert read_bytes(tmp_path, "all.txt") == bundle.all_text.encode("utf-8")
        assert dt < 20.0, f"persistence too slow: {dt:.2f}s"

    def test_rewrite_is_cheaper_than_the_first_write(self, tmp_path):
        items = [entry(build_node(path=f"/p{i}", ms=100.0 + (i % 100), geo=canada()))
                 for i in range(500)]
        bundle = build_outputs(items)
        policy = WriterPolicy(root=str(tmp_path))
        write_outputs(bundle, policy)
        second = write_outputs(bundle, policy)
        assert second.written == 0 and second.bytes_written == 0
