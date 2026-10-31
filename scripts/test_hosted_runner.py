import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_hosted_runner as setup


class HostedRunnerTests(unittest.TestCase):
    def test_local_and_self_hosted_environments_cannot_delete_sdks(self):
        for env in ({},{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted','RUNNER_OS':'Linux'}):
            with patch.dict(os.environ,env,clear=True), patch.object(setup.subprocess,'run') as command:
                with self.assertRaisesRegex(RuntimeError,'disposable'): setup.prepare()
                command.assert_not_called()

    def test_adequate_capacity_never_deletes_anything(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ,{
            'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux','GITHUB_WORKSPACE':temp
        },clear=True), patch.object(setup.shutil,'disk_usage',return_value=SimpleNamespace(free=31*setup.GB)), \
             patch.object(setup.subprocess,'run') as command:
            setup.prepare(); command.assert_not_called()

    def test_unexpected_sdk_symlink_is_never_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/'sdk').symlink_to(root,target_is_directory=True)
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux','GITHUB_WORKSPACE':temp},clear=True), \
                 patch.object(setup,'SDK_PATHS',(str(root/'sdk'),)), \
                 patch.object(setup.shutil,'disk_usage',return_value=SimpleNamespace(free=12*setup.GB)), \
                 patch.object(setup.subprocess,'run') as command:
                with self.assertRaisesRegex(RuntimeError,'unexpected'): setup.prepare()
                command.assert_not_called()

    def test_missing_sdks_do_not_relax_capacity_requirement(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ,{
            'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux','GITHUB_WORKSPACE':temp
        },clear=True), patch.object(setup,'SDK_PATHS',()), \
             patch.object(setup.shutil,'disk_usage',return_value=SimpleNamespace(free=12*setup.GB)), \
             patch.object(setup.subprocess,'run') as command:
            with self.assertRaisesRegex(RuntimeError,'30 GB'): setup.prepare()
            command.assert_not_called()
