from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from mdseval.runner import codex_cli
from scripts.contain import runtime as sealed
from tooling import starlette_product_a as product_a
from tooling import starlette_product_a_runtime as runtime


def published_lock() -> dict:
    lock = json.loads(runtime.LOCK_PATH.read_text(encoding="utf-8"))
    lock["status"] = "published"
    for number, profile in enumerate(lock["profiles"].values(), 1):
        digest = f"{number:064x}"
        profile["pull"] = f"{lock['repository']}@sha256:{digest}"
        profile["config_id"] = f"sha256:{number + 10:064x}"
    task_images = {
        task: profile["config_id"]
        for profile in lock["profiles"].values()
        for task in profile["tasks"]
    }
    lock["task_images"] = task_images
    return lock


class ProductAPublicRuntimeTests(unittest.TestCase):
    def test_checked_in_lock_is_published_and_complete(self) -> None:
        self.assertEqual(set(runtime._load_lock()["task_images"]), set(product_a.TASK_IDS))

    def test_published_lock_covers_exact_fixed_task_set(self) -> None:
        lock = published_lock()
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            loaded = runtime._load_lock(path)
        self.assertEqual(set(loaded["task_images"]), set(product_a.TASK_IDS))
        self.assertEqual(len(loaded["task_images"]), 18)

    def test_protocol_changes_only_v2_bindings_and_restores_v1(self) -> None:
        old_images = product_a.IMAGE_DIGESTS
        old_components, old_capabilities, old_required, old_disabled = product_a.COMPONENT_PATHS, codex_cli.SUBJECT_CAPABILITY_CONFIGS, sealed.SUBJECT_REQUIRED_CONFIGS, sealed.DISABLED_FEATURES
        lock = published_lock()
        with runtime.protocol(lock):
            self.assertEqual(product_a.IMAGE_DIGESTS, lock["task_images"])
            self.assertEqual(
                set(runtime.COMPONENTS),
                set(product_a.COMPONENT_PATHS) - set(old_components),
            )
            self.assertEqual((codex_cli.SUBJECT_CAPABILITY_CONFIGS.count("features.code_mode_host=true"), sealed.SUBJECT_REQUIRED_CONFIGS.count("features.code_mode_host=true"), "code_mode_host" in sealed.DISABLED_FEATURES), (1, 1, False)); self.assertNotIn("features.code_mode_host=false", codex_cli.SUBJECT_CAPABILITY_CONFIGS)
        self.assertIs(product_a.IMAGE_DIGESTS, old_images)
        self.assertIs(product_a.COMPONENT_PATHS, old_components); self.assertIs(codex_cli.SUBJECT_CAPABILITY_CONFIGS, old_capabilities); self.assertIs(sealed.SUBJECT_REQUIRED_CONFIGS, old_required); self.assertIs(sealed.DISABLED_FEATURES, old_disabled)

    def test_default_no_declines_download_before_activation(self) -> None:
        output: list[str] = []
        with tempfile.TemporaryDirectory() as name:
            auth_home = Path(name) / "codex"
            auth_home.mkdir()
            (auth_home / "auth.json").write_text("{}", encoding="utf-8")
            with mock.patch.dict(os.environ, {"MDSEVAL_CODEX_HOME": str(auth_home)}), \
                 mock.patch.object(runtime, "_load_lock", return_value=published_lock()), \
                 mock.patch.object(runtime, "_docker", return_value=["docker"]), \
                 mock.patch.object(runtime, "_images_ready", return_value=False), \
                 mock.patch.object(runtime, "_install") as install:
                with runtime.activate(lambda prompt: "", output.append) as ready:
                    self.assertFalse(ready)
            install.assert_not_called()
        self.assertIn("before request creation", "\n".join(output))

    def test_ready_runtime_is_active_only_inside_context(self) -> None:
        lock = published_lock()
        old_docker, old_pins = sealed.DOCKER, sealed.PINS
        with tempfile.TemporaryDirectory() as name:
            auth_home = Path(name) / "codex"
            auth_home.mkdir()
            (auth_home / "auth.json").write_text("{}", encoding="utf-8")
            with mock.patch.dict(os.environ, {"MDSEVAL_CODEX_HOME": str(auth_home)}), \
                 mock.patch.object(runtime, "_load_lock", return_value=lock), \
                 mock.patch.object(runtime, "_docker", return_value=["fixed-docker"]), \
                 mock.patch.object(runtime, "_images_ready", return_value=True), \
                 mock.patch.object(runtime, "_python_ready", return_value=True), \
                 mock.patch.object(runtime, "CACHE_ROOT", Path(name) / "cache"):
                with runtime.activate(output_fn=lambda line: None) as ready:
                    self.assertTrue(ready)
                    self.assertEqual(sealed.DOCKER, ["fixed-docker"])
                    self.assertEqual(product_a.IMAGE_DIGESTS, lock["task_images"])
        self.assertIs(sealed.DOCKER, old_docker)
        self.assertIs(sealed.PINS, old_pins)

    def test_python_tree_hash_detects_content_changes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "lib").mkdir()
            target = root / "lib" / "value"
            target.write_text("one", encoding="utf-8")
            first = runtime._tree_sha256(root)
            target.write_text("two", encoding="utf-8")
            self.assertNotEqual(runtime._tree_sha256(root), first)

    def test_recipe_pins_match_the_committed_profile_inputs(self) -> None:
        lock = json.loads(runtime.LOCK_PATH.read_text(encoding="utf-8"))
        recipe = (runtime.LOCK_PATH.parent / "Dockerfile").read_text(encoding="utf-8")
        for profile in lock["profiles"].values():
            source = runtime.ROOT / "tasks" / profile["source_task"] / "image-lock.json"
            self.assertEqual(sha256(source.read_bytes()).hexdigest(),
                             profile["image_lock_sha256"])
            self.assertIn(profile["image_lock_sha256"], recipe)
        self.assertIn(lock["codex"]["tarball_sha256"], recipe)
        self.assertIn(lock["python"]["source_image"], recipe)


if __name__ == "__main__":
    unittest.main()
