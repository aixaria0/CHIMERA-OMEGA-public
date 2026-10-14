"""Boundary tests. Fake compiler fixtures never stand in for native CI builds."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("omega_build", PROJECT / "tools/omega-build-evidence.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + b"\x03\x00\x3e\x00" + b"\0" * 44


class BuildEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="omega-build-unit-")
        cls.root = Path(cls.temporary.name)
        cls.source = cls.root / "source"
        subprocess.run(["git", "-C", str(PROJECT), "worktree", "add", "--detach", str(cls.source), BUILD.SOURCE],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.cargo, cls.rustc = cls.root / "fake-cargo", cls.root / "fake-rustc"
        cls.cargo.write_text("#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\n"
                             "if '-vV' in sys.argv: print('cargo 1.90.0 (TEST DOUBLE)')\n"
                             "elif 'build' in sys.argv:\n"
                             " p=Path(os.environ['CARGO_TARGET_DIR'])/'x86_64-unknown-linux-gnu/release/omega'\n"
                             " p.parent.mkdir(parents=True); p.write_bytes(" + repr(ELF) + ")\n")
        cls.rustc.write_text("#!/usr/bin/python3\nprint('rustc 1.90.0 (TEST DOUBLE)')\n")
        cls.cargo.chmod(0o755)
        cls.rustc.chmod(0o755)
        cls.evidence = cls.root / "synthetic-process-fixture"
        cls.record = BUILD.build(cls.source, cls.cargo, cls.rustc, cls.evidence, "unit-a")
        cls.selected = dict(expected_record=cls.record["record_digest"], expected_binary=BUILD.sha(ELF),
                            expected_controller=BUILD.sha((PROJECT / "tools/omega-build-evidence.py").read_bytes()),
                            expected_source=BUILD.SOURCE, expected_tree=BUILD.TREE, builder="unit-a")

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["git", "-C", str(PROJECT), "worktree", "remove", "--force", str(cls.source)], check=True)
        cls.temporary.cleanup()

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(dir=self.root)
        self.evidence_copy = Path(self.case.name) / "evidence"
        shutil.copytree(self.evidence, self.evidence_copy)

    def tearDown(self):
        self.case.cleanup()

    def rewrite(self, record, changed=()):
        for name in changed:
            raw = (self.evidence_copy / name).read_bytes()
            record["files"][name] = {"sha256": BUILD.sha(raw), "size": len(raw)}
        record["record_digest"] = BUILD.seal(record)
        (self.evidence_copy / "build.json").write_text(json.dumps(record))
        return dict(self.selected, expected_record=record["record_digest"])

    def test_exact_git_archive_tree_and_commit(self):
        tree, files = BUILD.archive_tree((self.evidence / "source.tar").read_bytes())
        self.assertEqual(tree, BUILD.TREE)
        self.assertEqual(len(files), 140)
        self.assertEqual(BUILD.commit_epoch((self.evidence / "source.commit").read_bytes(), BUILD.SOURCE, BUILD.TREE),
                         "1791349396")

    def test_saved_verification_does_not_spawn_compiler_or_verifier(self):
        with patch.object(BUILD, "run", side_effect=AssertionError("offline verifier spawned process")):
            self.assertEqual(BUILD.verify(self.evidence, **self.selected), self.record)

    def test_cli_scope_for_selected_synthetic_process_fixture(self):
        args = [sys.executable, str(PROJECT / "tools/omega-build-evidence.py"), "verify", "--evidence", str(self.evidence)]
        for name, value in self.selected.items():
            args += ["--" + name.replace("expected_", "expect-").replace("_", "-"), value]
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "PINNED_SAVED_BUILD_BYTES_ONLY")
        self.assertEqual(report["build_execution"], "ATTRIBUTED_NOT_ATTESTED")

    def test_external_selections_are_each_required(self):
        replacements = {"expected_record": "sha256:" + "0" * 64, "expected_binary": "sha256:" + "0" * 64,
                        "expected_controller": "sha256:" + "0" * 64, "expected_source": "0" * 40,
                        "expected_tree": "0" * 40, "builder": "wrong-builder"}
        for name, wrong in replacements.items():
            with self.subTest(name=name), self.assertRaises(BUILD.Rejected):
                BUILD.verify(self.evidence_copy, **dict(self.selected, **{name: wrong}))

    def test_rehashed_binary_replacement_still_fails_external_binary_selection(self):
        for name in ("build-1/omega", "build-2/omega"):
            (self.evidence_copy / name).write_bytes(ELF + b"replacement")
        selected = self.rewrite(copy.deepcopy(self.record), ("build-1/omega", "build-2/omega"))
        with self.assertRaisesRegex(BUILD.Rejected, "binary pin"):
            BUILD.verify(self.evidence_copy, **selected)

    def test_rehashed_source_replacement_still_fails_git_tree_selection(self):
        raw = (self.evidence_copy / "source.tar").read_bytes()
        stream = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as source, tarfile.open(fileobj=stream, mode="w") as dest:
            for member in source:
                dest.addfile(member, source.extractfile(member) if member.isfile() else None)
            extra = tarfile.TarInfo("injected-source.rs")
            extra.size = 6
            dest.addfile(extra, io.BytesIO(b"attack"))
        (self.evidence_copy / "source.tar").write_bytes(stream.getvalue())
        selected = self.rewrite(copy.deepcopy(self.record), ("source.tar",))
        with self.assertRaisesRegex(BUILD.Rejected, "source tree"):
            BUILD.verify(self.evidence_copy, **selected)

    def test_rehashed_commit_replacement_still_fails_source_commit_selection(self):
        path = self.evidence_copy / "source.commit"
        path.write_bytes(path.read_bytes() + b"\nchanged")
        selected = self.rewrite(copy.deepcopy(self.record), ("source.commit",))
        with self.assertRaisesRegex(BUILD.Rejected, "source commit"):
            BUILD.verify(self.evidence_copy, **selected)

    def test_log_tampering_is_not_a_successful_build_record(self):
        (self.evidence_copy / "build-1/stderr").write_bytes(b"invented successful build")
        with self.assertRaisesRegex(BUILD.Rejected, "file hash"):
            BUILD.verify(self.evidence_copy, **self.selected)

    def test_authority_extension_and_duplicate_json_fields_rejected(self):
        record = copy.deepcopy(self.record)
        record["authorized"] = True
        selected = self.rewrite(record)
        with self.assertRaises(BUILD.Rejected):
            BUILD.verify(self.evidence_copy, **selected)
        duplicate = json.dumps(self.record)[:-1] + ',"schema":"' + BUILD.SCHEMA + '"}'
        (self.evidence_copy / "build.json").write_text(duplicate)
        with self.assertRaises(BUILD.Rejected):
            BUILD.verify(self.evidence_copy, **self.selected)

    def test_same_occurrence_and_toolchain_disagreement_do_not_establish_corroboration(self):
        other = copy.deepcopy(self.record)
        other["acquisition"]["builder"] = "unit-b"
        with self.assertRaisesRegex(BUILD.Rejected, "same acquisition"):
            BUILD.comparison(self.record, other)
        other["acquisition"]["occurrence"] = "81c62c45-6c5e-4f32-9912-79df965a57a4"
        other["observed_tool_sha256"]["rustc"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(BUILD.Rejected, "tool_sha256"):
            BUILD.comparison(self.record, other)

    def test_agreement_preserves_unknown_independence_and_old_capture_link(self):
        other = copy.deepcopy(self.record)
        other["acquisition"]["builder"] = "unit-b"
        other["acquisition"]["occurrence"] = "81c62c45-6c5e-4f32-9912-79df965a57a4"
        other["record_digest"] = BUILD.seal(other)
        report = BUILD.comparison(self.record, other)
        self.assertEqual(report["dimensions"]["organizational_independence"], "UNKNOWN")
        self.assertEqual(report["dimensions"]["historical_capture_binary_binding"], "NOT_ASSESSED")

    def test_failed_run_and_json_boolean_are_rejected(self):
        for value in (1, True, 0.0):
            record = copy.deepcopy(self.record)
            record["runs"]["build-1"] = value
            selected = self.rewrite(record)
            with self.subTest(value=value), self.assertRaises(BUILD.Rejected):
                BUILD.verify(self.evidence_copy, **selected)

    def test_symlink_extra_missing_and_oversized_members_rejected(self):
        path = self.evidence_copy / "build-1/omega"
        raw = path.read_bytes()
        path.unlink()
        with self.assertRaises(BUILD.Rejected):
            BUILD.verify(self.evidence_copy, **self.selected)
        path.symlink_to(self.evidence / "build-1/omega")
        with self.assertRaises(BUILD.Rejected):
            BUILD.verify(self.evidence_copy, **self.selected)
        path.unlink()
        path.write_bytes(raw)
        extra = self.evidence_copy / "authority.json"
        extra.write_text("{}")
        with self.assertRaises(BUILD.Rejected):
            BUILD.verify(self.evidence_copy, **self.selected)
        extra.unlink()
        with (self.evidence_copy / "build.json").open("wb") as stream:
            stream.truncate(BUILD.MAX_RECORD + 1)
        with self.assertRaises(BUILD.Rejected):
            BUILD.verify(self.evidence_copy, **self.selected)

    def test_archive_paths_duplicates_and_links_rejected(self):
        for kind in ("../escape", "link", "duplicate"):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as archive:
                member = tarfile.TarInfo("../escape" if kind == "../escape" else "file")
                if kind == "link":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/tmp/target"
                archive.addfile(member)
                if kind == "duplicate":
                    archive.addfile(member)
            with self.subTest(kind=kind), self.assertRaises(BUILD.Rejected):
                BUILD.archive_tree(stream.getvalue())

    def test_existing_output_inside_source_and_dirty_checkout_rejected(self):
        for path in (self.evidence, self.source / "output"):
            with self.assertRaises(BUILD.Rejected):
                BUILD.build(self.source, self.cargo, self.rustc, path, "unit-a")
        dirty = self.source / "unreviewed.rs"
        dirty.write_text("unreviewed")
        try:
            with self.assertRaisesRegex(BUILD.Rejected, "dirty"):
                BUILD.build(self.source, self.cargo, self.rustc, Path(self.case.name) / "out", "unit-a")
        finally:
            dirty.unlink()

    def test_process_output_timeout_and_stdin_boundaries(self):
        with self.assertRaisesRegex(BUILD.Rejected, "output limit"):
            BUILD.run([sys.executable, "-c", "print('x'*100000)"], cwd=self.root, env=os.environ, timeout=5, limit=100)
        with self.assertRaisesRegex(BUILD.Rejected, "timeout"):
            BUILD.run([sys.executable, "-c", "import time; time.sleep(3)"], cwd=self.root, env=os.environ, timeout=0.1)
        code, stdout, _ = BUILD.run([sys.executable, "-c", "import sys; print(len(sys.stdin.read()))"],
                                    cwd=self.root, env=os.environ, timeout=5)
        self.assertEqual((code, stdout), (0, b"0\n"))


if __name__ == "__main__":
    unittest.main()
