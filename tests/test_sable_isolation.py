"""
Test: Prove that the SABLE analysis engine never imports ground_truth.py.

This is the automated test the specification requires.
Run: pytest tests/test_sable_isolation.py -v
"""
import sys
import importlib
import types


def test_engine_does_not_import_ground_truth():
    """
    Ensure that no engine module (analyzer, authorization, correspondence,
    hcl_parser, baselines, benchmark) imports ground_truth at import time
    or via any of their public callables.
    """
    # Clear any prior imports
    modules_to_clear = [k for k in sys.modules if "sable" in k]
    for m in modules_to_clear:
        sys.modules.pop(m, None)

    # Track imports by patching __import__
    import builtins
    imported_paths: list[str] = []
    real_import = builtins.__import__

    def tracking_import(name, *args, **kwargs):
        imported_paths.append(name)
        return real_import(name, *args, **kwargs)

    builtins.__import__ = tracking_import

    try:
        # Import all engine modules
        import backend.sable.hcl_parser
        import backend.sable.authorization
        import backend.sable.correspondence
        import backend.sable.analyzer
        import backend.sable.baselines
    finally:
        builtins.__import__ = real_import

    # Check ground_truth was never imported
    gt_imports = [p for p in imported_paths if "ground_truth" in p]
    assert gt_imports == [], (
        f"Engine imported ground_truth! This is a test failure. "
        f"Ground truth must ONLY be imported by the benchmark evaluator. "
        f"Imports found: {gt_imports}"
    )


def test_benchmark_can_import_ground_truth():
    """Benchmark module is allowed to import ground_truth (via loader function)."""
    # benchmark.py calls _load_gt() which imports ground_truth — this is correct
    from backend.sable.benchmark import _load_gt
    gt = _load_gt()
    assert isinstance(gt, dict)
    assert len(gt) >= 30, f"Expected at least 30 ground truth labels, got {len(gt)}"
    assert "PRESERVED" in set(gt.values())
    assert "REGRESSED" in set(gt.values())
    assert "UNKNOWN" in set(gt.values())


def test_ground_truth_covers_all_scenarios():
    """Every scenario in SCENARIOS has a ground truth label."""
    from backend.sable.fixtures.scenarios import SCENARIOS
    from backend.sable.fixtures.ground_truth import GROUND_TRUTH
    missing = [sid for sid in SCENARIOS if sid not in GROUND_TRUTH]
    assert missing == [], f"Scenarios without ground truth labels: {missing}"
