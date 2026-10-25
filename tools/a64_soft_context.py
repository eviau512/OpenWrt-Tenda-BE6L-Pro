# SPDX-License-Identifier: MIT
"""Shared paths for the isolated, nonstandard AArch64 soft-float experiment."""
from pathlib import Path
import os

BASE=Path(__file__).resolve().parents[1]
SDK=Path(os.environ.get('BE6L_ARM64_SDK','/root/be6l-openwrt/arm64-source'))
ROOT=Path(os.environ.get('BE6L_SOFT_ROOT','/root/be6l-openwrt/a64-soft-experiment'))
EPOCH='1792420077'
for path in (SDK,ROOT):
    assert path.is_absolute() and not any(x.isspace() for x in str(path)), 'Use an absolute path without whitespace'
(BASE/'logs').mkdir(exist_ok=True)
(BASE/'artifacts').mkdir(exist_ok=True)
