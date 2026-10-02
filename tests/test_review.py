import unittest, json, base64, hashlib, tempfile, pathlib, datetime, copy, subprocess, sys, os, struct
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ObjectIdentifier
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,ec,rsa
from tuf_top_level_review import audit
from tuf_top_level_review.common import ReviewError,load,read
UTC=datetime.timezone.utc
def enc(b):return base64.b64encode(b).decode()
def url(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def pemkey(k):return k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def certs(leaf_extensions=(),issuer_extensions=()):
    now=datetime.datetime.now(UTC).replace(microsecond=0);issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048);leaf_key=ed25519.Ed25519PrivateKey.generate()
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic Review CA')])
    ku=x509.KeyUsage(True,False,False,False,False,True,True,False,False)
    builder=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(issuer_key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(ku,True).add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),False)
    for ext,critical in issuer_extensions:builder=builder.add_extension(ext,critical)
    issuer=builder.sign(issuer_key,hashes.SHA256())
    builder=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic.invalid')])).issuer_name(subject).public_key(leaf_key.public_key()).serial_number(10).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
    for ext,critical in leaf_extensions:builder=builder.add_extension(ext,critical)
    leaf=builder.sign(issuer_key,hashes.SHA256());return now,issuer_key,issuer,leaf_key,leaf
def cpem(c):return c.public_bytes(serialization.Encoding.PEM).decode()
def save_example(d):
    if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':return
    out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True)
    (out/'valid.json').write_text(json.dumps(d,indent=2)+'\n')
class CommonTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_input(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
            with self.assertRaises(ReviewError):load(raw)
    def test_input_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t);(p/'file').write_text('x');(p/'link').symlink_to(p/'file');os.mkfifo(p/'pipe')
            for q in (p/'link',p/'pipe'):
                with self.assertRaises((ReviewError,OSError)):read(str(q))
    def test_missing_fields_and_cli_exit(self):
        with self.assertRaises((ReviewError,KeyError)):audit({})
        proc=subprocess.run([sys.executable,'-m','tuf_top_level_review','-'],input=b'{}',capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,1);self.assertEqual(json.loads(proc.stdout)['status'],'FAIL');self.assertFalse(json.loads(proc.stdout)['complete'])

class TufTests(unittest.TestCase):
    def setUp(self):
        self.k=ed25519.Ed25519PrivateKey.generate();public=self.k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex();self.now=datetime.datetime.now(UTC).replace(microsecond=0);common={'spec_version':'1.0.31','version':1,'expires':(self.now+datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')}
        self.root={'_type':'root',**common,'consistent_snapshot':False,'keys':{'key':{'keytype':'ed25519','scheme':'ed25519','keyval':{'public':public}}},'roles':{r:{'keyids':['key'],'threshold':1} for r in ('root','timestamp','snapshot','targets')}}
        data=b'synthetic signed target';self.targets=self.sign({'_type':'targets',**common,'targets':{'release.txt':{'length':len(data),'hashes':{'sha256':hashlib.sha256(data).hexdigest()}}}});self.snapshot=self.sign({'_type':'snapshot',**common,'meta':{'targets.json':self.info(self.targets)}});self.timestamp=self.sign({'_type':'timestamp',**common,'meta':{'snapshot.json':self.info(self.snapshot)}});root=self.sign(self.root)
        self.d={'trusted_root':enc(root),'trusted_root_sha256':hashlib.sha256(root).hexdigest(),'root_updates':[],'timestamp':enc(self.timestamp),'snapshot':enc(self.snapshot),'targets':enc(self.targets),'prior_versions':{r:1 for r in ('root','timestamp','snapshot','targets')},'target_files':{'release.txt':enc(data)},'now':self.now.isoformat()}
    def sign(self,signed):
        raw=json.dumps(signed,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode();return json.dumps({'signed':signed,'signatures':[{'keyid':'key','sig':self.k.sign(raw).hex()}]},sort_keys=True,separators=(',',':')).encode()
    def info(self,raw):return {'version':1,'length':len(raw),'hashes':{'sha256':hashlib.sha256(raw).hexdigest()}}
    def test_full_chain(self):self.assertTrue(audit(self.d)['verified']);save_example(self.d)
    def test_root_rotation(self):
        new=copy.deepcopy(self.root);new['version']=2;self.d['root_updates']=[enc(self.sign(new))];self.assertEqual(audit(self.d)['versions']['root'],2)
    def test_tamper_expiry_rollback_missing_target_hash_link(self):
        mutations=[lambda d:d.update(trusted_root_sha256='0'*64),lambda d:d.update(now='2099-01-01T00:00:00Z'),lambda d:d['prior_versions'].update(timestamp=2),lambda d:d.update(target_files={}),lambda d:d['target_files'].update({'release.txt':enc(b'changed')}),lambda d:d.update(snapshot=enc(self.snapshot+b' '))]
        for change in mutations:
            d=copy.deepcopy(self.d);change(d)
            with self.assertRaises(ReviewError):audit(d)
    def test_canonical_upstream_differential_and_semver(self):
        from tuf_top_level_review.audit import canonical
        from securesystemslib.formats import encode_canonical
        vectors=[{'keys':{'quote':'a"b','slash':'a/b','backslash':'a'+chr(92)+'b','unicode':'日本語'}},self.root,{'negative':-7,'array':[True,False,None,0]}]
        for v in vectors:self.assertEqual(canonical(v),encode_canonical(v).encode())
        with self.assertRaises(ReviewError):canonical({'unsupported':chr(10)})
        for spec in (1.0,'2.0.0','1.0','1.x.0'):
            root=copy.deepcopy(self.root);root['spec_version']=spec;raw=self.sign(root);d=copy.deepcopy(self.d);d.update(trusted_root=enc(raw),trusted_root_sha256=hashlib.sha256(raw).hexdigest())
            with self.assertRaises(ReviewError):audit(d)
    def test_signature_and_unsupported_delegation(self):
        ts=json.loads(self.timestamp);ts['signatures'][0]['sig']='0'*128;self.d['timestamp']=enc(json.dumps(ts).encode())
        with self.assertRaises(ReviewError):audit(self.d)

if __name__=="__main__":unittest.main()
