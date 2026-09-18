import pytest
from core.scanner import _build_scan_args, is_root

def test_build_scan_args_tcp():
    args = _build_scan_args(mode="tcp", aggressive=False, root=False)
    assert "-sT" in args

def test_build_scan_args_aggressive():
    args = _build_scan_args(mode="tcp", aggressive=True, root=False)
    assert "-sT" in args
    assert "-A" in args

def test_is_root():
    # Since tests run as non-root usually, it should be False
    assert isinstance(is_root(), bool)
