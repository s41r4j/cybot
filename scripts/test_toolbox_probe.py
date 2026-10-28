import copy
import unittest
from unittest.mock import patch
import toolbox_probe

class ProbeTests(unittest.TestCase):
    def test_bare_gitleaks_version_is_parsed(self):
        with patch.dict(toolbox_probe.BINARIES, {'gitleaks': ('/bin/gitleaks', 'version')}, clear=True):
            output = 'CYBOT_HASH gitleaks ' + 'a'*64 + ' /bin/gitleaks\nCYBOT_VERSION gitleaks\n8.30.1\nCYBOT_END\nCYBOT_PACKAGES\nnmap=7.93\nCYBOT_END'
            report = toolbox_probe.parse(output)
            self.assertEqual(report['binaries']['gitleaks']['reported_version'], '8.30.1')

    def test_runtime_binary_drift_is_rejected(self):
        expected={'binaries':{'httpx':{'sha256':'expected','reported_version':'1.10.0'}},'packages':{}}
        drifted=copy.deepcopy(expected);drifted['binaries']['httpx']['sha256']='different'
        with self.assertRaisesRegex(RuntimeError,'hashes'): toolbox_probe.validate_runtime(drifted,expected)

    def test_package_drift_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'package versions'):
            toolbox_probe.validate_source({'binaries':{},'packages':{'nmap':'new'}},{'tools':{},'packages':{'nmap':'pinned'}})

    def test_version_mismatch_is_explicit_not_normalized_away(self):
        source={'tools':{'dnsx':{'version':'v1.3.0','reported_version':'1.2.3'}},'packages':{}}
        toolbox_probe.validate_source({'binaries':{'dnsx':{'reported_version':'1.2.3'}},'packages':{}},source)
        with self.assertRaisesRegex(RuntimeError,'dnsx'):
            toolbox_probe.validate_source({'binaries':{'dnsx':{'reported_version':'1.4.0'}},'packages':{}},source)

    def test_missing_probe_fields_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError,'Incomplete'):
            toolbox_probe.parse('CYBOT_HASH httpx 123')

if __name__=='__main__': unittest.main()
