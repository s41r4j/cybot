import base64
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from package_audit_controls import image_fixture
import package_audit_report as audit


class PackageAuditTests(unittest.TestCase):
    def fixture(self):
        config=json.dumps({'architecture':'amd64','os':'linux'}).encode()
        identity='sha256:'+hashlib.sha256(config).hexdigest()
        sbom={'source':{'type':'image','metadata':{'imageID':identity,'config':base64.b64encode(config).decode()}},
              'distro':{'id':'debian','versionID':'12'},'artifacts':[{'id':'os1','name':'base-files','version':'12.4','type':'deb','purl':'pkg:deb/debian/base-files@12.4'}]}
        scan={'source':{'type':'image','target':{'imageID':identity}},'descriptor':{'name':'grype','version':'0.116.1','configuration':{}},'matches':[]}
        return identity,sbom,scan

    def test_config_hash_platform_and_installed_packages_are_required(self):
        identity,sbom,_=self.fixture()
        self.assertEqual(len(audit.inventory(sbom,identity,'amd64')[0]),1)
        for key,value in [('imageID','sha256:'+'0'*64),('config',base64.b64encode(b'{}').decode())]:
            invalid=copy.deepcopy(sbom);invalid['source']['metadata'][key]=value
            with self.assertRaises(RuntimeError):audit.inventory(invalid,identity,'amd64')
        with self.assertRaises(RuntimeError):audit.inventory(sbom,identity,'arm64')
        sbom['artifacts']=[]
        with self.assertRaisesRegex(RuntimeError,'empty'):audit.inventory(sbom,identity,'amd64')

    def test_suppressed_matches_are_retained_and_foreign_package_matches_fail(self):
        identity,_,scan=self.fixture()
        row={'artifact':{'id':'os1','name':'base-files','version':'12.4','type':'deb'},'vulnerability':{'id':'CVE-fixture','severity':'Low'}}
        scan['ignoredMatches']=[row]
        self.assertTrue(audit.findings(scan,identity,{'os1'},'0.116.1')[0]['ignored'])
        row['artifact']['id']='not-cataloged'
        with self.assertRaises(RuntimeError):audit.findings(scan,identity,{'os1'},'0.116.1')
        scan['ignoredMatches']=[];scan['descriptor']['configuration']['only-fixed']=True
        with self.assertRaisesRegex(RuntimeError,'filtered'):audit.findings(scan,identity,{'os1'},'0.116.1')

    def test_unmeasured_go_and_native_code_cannot_be_hidden_by_empty_matches(self):
        identity,sbom,scan=self.fixture()
        sbom['artifacts'].append({'id':'go1','name':'fixture','version':'1.0.0','type':'go-module','locations':[{'path':'/usr/bin/unlisted'}],
            'metadata':{'goCompiledVersion':'go1.26.10','goBuildSettings':[{'key':'CGO_ENABLED','value':'1'}]}})
        lock={'go_tools':{'grype':'0.116.1'},'database':{},'native_components':{'supplychain':[]}}
        result=audit.summarize(sbom,scan,identity,'amd64','supplychain',{'binaries':{}},lock)
        self.assertEqual(result['status'],'blocked')
        self.assertEqual(result['unmeasured_go_binaries'],['/usr/bin/unlisted'])
        self.assertEqual(result['unscanned_cgo_binaries'],['/usr/bin/unlisted'])

    def test_missing_native_package_identity_remains_unmapped(self):
        measured={'binaries':{'nmap':{'sha256':'0'*64}},'packages':{'nmap':'7.93'}}
        result=audit.mapped_components('core',measured,[],['nmap'])
        self.assertEqual(result[0]['status'],'unmapped')

    def test_database_age_and_boolean_only_clearance_are_rejected(self):
        for stamp in [datetime.now(timezone.utc)-timedelta(hours=73),datetime.now(timezone.utc)+timedelta(minutes=6)]:
            with self.assertRaises(RuntimeError):audit.database_fresh({'created':stamp.isoformat()})
        with self.assertRaises(ValueError):audit.validate_clear_report({'status':'passed'},{},'sha256:'+'0'*64,'core')

    def test_fixture_archives_bind_distinct_image_configs(self):
        with tempfile.TemporaryDirectory() as temp:
            positive=image_fixture(Path(temp)/'positive.tar','amd64',True)
            negative=image_fixture(Path(temp)/'negative.tar','amd64',False)
            self.assertNotEqual(positive,negative)
            self.assertLess((Path(temp)/'positive.tar').stat().st_size,65536)

    def test_clear_package_report_requires_explicit_empty_gaps_and_checked_scanners(self):
        identity,sbom,_=self.fixture()
        policy={'database':{'created':datetime.now(timezone.utc).isoformat()},'max_database_age_hours':72,
                'go_tools':{'syft':'1.50.0','grype':'0.116.1'},'native_components':{'supplychain':[],'core':['nmap']}}
        report={'schema_version':1,'status':'passed','image_id':identity,'network':'none','database':policy['database'],
                'inventory':sbom['artifacts'],'components':[], 'controls':dict.fromkeys(['positive','negative','failure'],'passed'),
                'scanners':{name:{'status':'passed','reported_version':version,'binary_sha256':'0'*64,'source_provenance_sha256':'1'*64,'source_modules':[{'status':'passed'}]} for name,version in policy['go_tools'].items()}}
        for key in ('image_archive_sha256','database_file_sha256','sbom_sha256','scanner_report_sha256'):report[key]='2'*64
        for key in ('findings','unmapped_components','unmeasured_go_binaries','unknown_version_packages','unscanned_cgo_binaries'):report[key]=[]
        audit.validate_clear_report(report,policy,identity,'supplychain')
        with self.assertRaisesRegex(ValueError,'required native'):audit.validate_clear_report(report,policy,identity,'core')
        invalid=copy.deepcopy(report);invalid.pop('unscanned_cgo_binaries')
        with self.assertRaises(ValueError):audit.validate_clear_report(invalid,policy,identity,'supplychain')
        invalid=copy.deepcopy(report);invalid['scanners']['grype']['source_modules']=[]
        with self.assertRaisesRegex(ValueError,'source advisory'):audit.validate_clear_report(invalid,policy,identity,'supplychain')


if __name__=='__main__':unittest.main()
