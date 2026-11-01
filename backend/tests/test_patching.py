import unittest
from app.services.patching import validate_diff
from app.services.source import safe_relative_path
from fastapi import HTTPException

class PatchValidationTests(unittest.TestCase):
    def test_accepts_single_file_diff_shape(self):
        patch="diff --git a/app.py b/app.py\nindex 1111111..2222222 100644\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"
        self.assertTrue(validate_diff(patch,"app.py")[0])
    def test_rejects_path_mismatch(self):
        patch="diff --git a/other.py b/other.py\nindex 1111111..2222222 100644\n--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-old\n+new\n"
        self.assertFalse(validate_diff(patch,"app.py")[0])
    def test_rejects_policy_and_ci_paths(self):
        self.assertFalse(validate_diff("diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml\n",".gitlab-ci.yml")[0])

    def test_rejects_traversal_paths(self):
        self.assertFalse(validate_diff("diff --git a/../app.py b/../app.py\n--- a/../app.py\n+++ b/../app.py\n","../app.py")[0])

    def test_rejects_mismatched_unified_headers(self):
        patch="diff --git a/app.py b/app.py\n--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-old\n+new\n"
        self.assertFalse(validate_diff(patch,"app.py")[0])

    def test_source_path_excludes_ci_and_workflow_controls(self):
        for raw in [".gitlab-ci.yml", ".github/workflows/build.yml", "policy/secure-coding.md", "../secret.py"]:
            with self.subTest(path=raw):
                with self.assertRaises(HTTPException):
                    safe_relative_path(raw)

if __name__=="__main__": unittest.main()
