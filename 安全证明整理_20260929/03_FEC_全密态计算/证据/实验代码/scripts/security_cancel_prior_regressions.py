"""Rerun prior suites and apply their authentication-boundary tests to new generation."""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prior = ROOT / 'security_fixes/20260916'
    suite = unittest.defaultTestLoader.discover(str(prior / 'tests'), pattern='test_*.py')
    log = io.StringIO()
    baseline = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    spec = importlib.util.spec_from_file_location('cancel_auth_boundary_regression', prior / 'tests/test_generation_boundary.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ROOT = ROOT / 'security_fixes/20260917_cancel'
    candidate = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(mod))
    report = {'scope': 'existing synthetic local suites plus actual candidate generation authentication boundary',
              'prior_tests': baseline.testsRun, 'prior_passed': baseline.wasSuccessful(),
              'candidate_auth_boundary_tests': candidate.testsRun, 'candidate_passed': candidate.wasSuccessful(),
              'log': log.getvalue(), 'passed': baseline.wasSuccessful() and candidate.wasSuccessful()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: v for k, v in report.items() if k != 'log'}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
