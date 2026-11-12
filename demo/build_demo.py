#!/usr/bin/env python3
"""Regenerate the checked-in demo .wasm files from their .wat sources."""

from pathlib import Path

import wasmtime

HERE = Path(__file__).resolve().parent

for name in ("classify", "loop", "spam"):
    wat_path = HERE / f"{name}.wat"
    wasm_path = HERE / f"{name}.wasm"
    wasm_path.write_bytes(wasmtime.wat2wasm(wat_path.read_bytes()))
    print(f"{wasm_path.name}: {wasm_path.stat().st_size} bytes")
