#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

from decode_npm_loader import decode_sample

BASE = Path(__file__).resolve().parents[1]
EXPECTED = {
    "ide_loader_sha256": "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb",
    "npm_loader_sha256": "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668",
    "second_stage_sha256": "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def has_process_property(text, name):
    return any(
        marker in text
        for marker in (f"process.{name}", f'process["{name}"]', f"process['{name}']")
    )


def loader_features(text, ide):
    return {
        "bun_1_3_13": "1.3.13" in text,
        "installed_bun_executes_payload": ("if (hc" if ide else "](hc") in text,
        "platform_architecture_mapping": has_process_property(text, "platform") and has_process_property(text, "arch"),
        "internal_zip_fallback": "function xn" in text and "function xb" in text,
        "temporary_download_cleanup": "rmSync" in text,
        "ci_skip_absent": not any(
            marker in text
            for marker in (
                "skipInstallHook",
                "process.env.CI",
                "process.env.GITHUB_ACTIONS",
                "process.env.GITLAB_CI",
                "process.env.RUNNER_ENVIRONMENT",
            )
        ),
    }


def main():
    ide_loader_path = BASE / "evidence/ide/setup.mjs"
    npm_loader_path = BASE / "evidence/npm/setup.mjs"
    ide_stage_path = BASE / "evidence/ide/math_init.js"
    npm_stage_path = BASE / "evidence/npm/Math_Symbol.js"
    ide_text = ide_loader_path.read_text()
    npm_text = decode_sample(npm_loader_path.read_text())
    ide_features = loader_features(ide_text, ide=True)
    npm_features = loader_features(npm_text, ide=False)
    shared = {
        key: ide_features[key] and npm_features[key]
        for key in ide_features
    }
    result = {
        "loaders": [
            {
                "distribution_path": "IDE source checkout",
                "sha256": digest(ide_loader_path),
                "bytes": ide_loader_path.stat().st_size,
                "payload_name": "math_init.js",
                "features": ide_features,
            },
            {
                "distribution_path": "npm package",
                "sha256": digest(npm_loader_path),
                "bytes": npm_loader_path.stat().st_size,
                "payload_name": "Math_Symbol.js",
                "features": npm_features,
            },
        ],
        "published_loader_hashes_match": (
            digest(ide_loader_path) == EXPECTED["ide_loader_sha256"]
            and digest(npm_loader_path) == EXPECTED["npm_loader_sha256"]
        ),
        "second_stage": {
            "byte_identical": ide_stage_path.read_bytes() == npm_stage_path.read_bytes(),
            "sha256": digest(ide_stage_path),
            "published_hash_matches": digest(ide_stage_path) == EXPECTED["second_stage_sha256"],
            "bytes": ide_stage_path.stat().st_size,
        },
        "shared_behavior": shared,
        "semantic_match": all(shared.values()),
    }
    output = BASE / "analysis/comparison.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    assert result["published_loader_hashes_match"]
    assert result["second_stage"]["byte_identical"]
    assert result["second_stage"]["published_hash_matches"]
    assert result["semantic_match"]


if __name__ == "__main__":
    main()
