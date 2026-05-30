"""
run_tests.py — Run all unit tests from the project root.
Usage:  python run_tests.py
"""
import unittest
import sys

loader = unittest.TestLoader()
suite  = loader.discover("tests", pattern="test_*.py")
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
