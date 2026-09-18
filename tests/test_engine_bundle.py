import hashlib
import json
from pathlib import Path
import subprocess
import sys


SCRIPT = Path(__file__).parents[1] / "scripts" / "validate_engine_bundle.py"


def _manifest(root: Path, *, mutate: bool = False) -> Path:
    binary = root / "bin" / "qemu-system-aarch64"
    binary.parent.mkdir()
    binary.write_bytes(b"qemu")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if mutate:
        digest = "0" * 64
    manifest = root / "engine-build.json"
    manifest.write_text(json.dumps({
        "schema_version": 1,
        "status": "complete",
        "dirty_source": False,
        "patches_applied": True,
        "targets": ["aarch64-softmmu"],
        "executables": {"aarch64-softmmu": "bin/qemu-system-aarch64"},
        "executable_sha256": {"aarch64-softmmu": digest},
    }), encoding="utf-8")
    return manifest


def test_validates_complete_bundle(tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT), str(_manifest(tmp_path))],
                            check=False, capture_output=True, text=True)
    assert result.returncode == 0
    assert json.loads(result.stdout)["valid"] is True


def test_rejects_changed_executable(tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT), str(_manifest(tmp_path, mutate=True))],
                            check=False, capture_output=True, text=True)
    assert result.returncode == 2
    assert "digest mismatch" in result.stdout
