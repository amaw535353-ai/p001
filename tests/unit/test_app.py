import importlib.util
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location("app",Path(__file__).parents[2]/"services/common/app.py")
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
class AppTests(unittest.TestCase):
    def test_simulator_determinism(self):
        self.assertEqual(a.infer("synthetic"),a.infer("synthetic"))
        self.assertNotEqual(a.infer("synthetic"),a.infer("other"))
        self.assertIs(a.infer("synthetic")["simulator"],True)
    def test_caller_bound_to_tenant(self):
        self.assertTrue(a.authorized("Bearer p001-fixture-tenant-a","tenant-a"))
        self.assertFalse(a.authorized("Bearer p001-fixture-tenant-b","tenant-a"))
        self.assertFalse(a.authorized("","tenant-a"))
    def test_key_scope(self):
        self.assertEqual(a.object_key("fixture-a"),"fixture-a")
        for key in ["../tenant-b", "fixture-a?x", "", "tenant-b/fixture-a"]:
            with self.assertRaises(ValueError):a.object_key(key)
    def test_endpoint_fails_closed(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"P001_S3_ENDPOINT":"https://unapproved.invalid"}):
            with self.assertRaisesRegex(ValueError,"unapproved emulator endpoint"):a.s3()
