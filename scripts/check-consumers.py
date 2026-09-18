#!/usr/bin/env python3
"""Build supported features outside workspace feature unification."""
import argparse
import tarfile
import tomllib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = [
    ("gatekeep", []), ("gatekeep", ["test"]),
    ("gatekeep-axum", []), ("gatekeep-fluent", []), ("gatekeep-keepsake", []),
    ("gatekeep-sqlx", ["postgres"]), ("gatekeep-sqlx", ["sqlite"]),
    ("gatekeep-sqlx", ["mysql"]),
]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--packaged", action="store_true", help="build extracted crate archives instead of workspace sources")
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="gatekeep-consumers-") as directory:
    base = Path(directory)
    sources = {local.name: local for local in (ROOT / "crates").iterdir() if (local / "Cargo.toml").exists()}
    if args.packaged:
        for name, local in sources.items():
            version = tomllib.loads((local / "Cargo.toml").read_text())["package"]["version"]
            with tarfile.open(ROOT / "target" / "package" / f"{name}-{version}.crate") as archive:
                archive.extractall(base / "archives", filter="data")
            sources[name] = base / "archives" / f"{name}-{version}"
    for index, (package, features) in enumerate(PACKAGES):
        consumer = base / str(index)
        (consumer / "src").mkdir(parents=True)
        dependency = "{ path = " + json.dumps(str(sources[package]))
        dependency += ", default-features = false, features = " + json.dumps(features) + " }"
        manifest = '[package]\nname = "isolated-consumer"\nversion = "0.0.0"\nedition = "2024"\n'
        manifest += "[dependencies]\n" + package + " = " + dependency + "\n[patch.crates-io]\n"
        for name, local in sources.items():
            manifest += name + " = { path = " + json.dumps(str(local)) + " }\n"
        (consumer / "Cargo.toml").write_text(manifest)
        (consumer / "src" / "main.rs").write_text("fn main() {}\n")
        print(f"Checking isolated {package} {features}", flush=True)
        env = os.environ | {"CARGO_TARGET_DIR": str(ROOT / "target" / "consumers")}
        subprocess.run(["cargo", "check", "--offline", "--manifest-path", str(consumer / "Cargo.toml")], check=True, env=env)
