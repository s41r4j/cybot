"""Create harmless installed-package Docker archives; no daemon or network required."""
import hashlib
import io
import json
import tarfile


def archive_bytes(files):
    content = io.BytesIO()
    with tarfile.open(fileobj=content,mode='w') as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name); member.size=len(data); member.mode=0o644
            archive.addfile(member,io.BytesIO(data))
    return content.getvalue()


def image_fixture(path, arch, vulnerable):
    status = 'Package: base-files\nStatus: install ok installed\nArchitecture: '+arch+'\nVersion: 12.4\n\n'
    if vulnerable:
        status += 'Package: libssl3\nStatus: install ok installed\nArchitecture: '+arch+'\nSource: openssl\nVersion: 3.0.0-1\n\n'
    package = {'name':'lodash','version':'4.17.20' if vulnerable else '9999.0.0','license':'MIT'}
    layer = archive_bytes({'etc/os-release':b'ID=debian\nVERSION_ID=12\nPRETTY_NAME="Debian GNU/Linux 12"\n',
        'var/lib/dpkg/status':status.encode(),'app/node_modules/lodash/package.json':json.dumps(package).encode()})
    config = json.dumps({'architecture':arch,'os':'linux','rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(layer).hexdigest()]}}).encode()
    image_id = 'sha256:'+hashlib.sha256(config).hexdigest()
    config_name = image_id.removeprefix('sha256:')+'.json'
    manifest = [{'Config':config_name,'RepoTags':None,'Layers':['layer.tar']}]
    path.write_bytes(archive_bytes({'layer.tar':layer,config_name:config,'manifest.json':json.dumps(manifest).encode()}))
    return image_id
