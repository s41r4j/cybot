import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import browser_profile


class BrowserProfileTests(unittest.TestCase):
    def test_version_text_cannot_replace_the_pinned_cli_checksum(self):
        lock = json.loads((browser_profile.toolbox.ROOT/'docker/toolbox/browser.lock.json').read_text())
        chrome = lock['packages']['amd64']['chromium'].split('-')[0]
        versions = {'cybot':'0.1.0','agent-browser':lock['agent_browser']['version'],'chromium':chrome,'chromium-launcher':chrome,'python':'3.11.2'}
        def output(corrupt=False):
            text = ''
            for name,version in versions.items():
                digest = lock['agent_browser']['assets']['amd64']['sha256'] if name == 'agent-browser' and not corrupt else '0'*64
                text += f'CYBOT_HASH {name} {digest} /fixture/{name}\nCYBOT_VERSION {name}\n{version}\nCYBOT_END\n'
            text += 'CYBOT_BROWSER_DATA\n'+json.dumps({'data':{},'packages':lock['packages']['amd64'],'all_packages':lock['packages']['amd64']})+'\nCYBOT_END\n'
            return text
        with tempfile.TemporaryDirectory() as temp, patch.object(browser_profile.toolbox,'STATE',Path(temp)), patch.object(browser_profile.toolbox,'ARCH','amd64'):
            def run(*args,**kwargs):
                self.assertEqual(kwargs['network'],'none')
                kwargs['output'].write_text(output())
            with patch.object(browser_profile.toolbox,'run',side_effect=run):
                self.assertEqual(browser_profile.probe('owned-fixture')['binaries']['agent-browser']['reported_version'],'0.40.0')
            def altered(*args,**kwargs): kwargs['output'].write_text(output(corrupt=True))
            with patch.object(browser_profile.toolbox,'run',side_effect=altered):
                with self.assertRaisesRegex(RuntimeError,'checksum-pinned release'):
                    browser_profile.probe('owned-fixture')


if __name__ == '__main__': unittest.main()
