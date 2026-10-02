from .common import *
from .crypto import *
from pathlib import PurePosixPath

def canonical(v):
    def walk(x):
        need(x is None or isinstance(x,(str,bool,dict,list)) or type(x) is int,"noncanonical number type")
        if isinstance(x,str):need(all(ord(c)>=32 and not 0xD800<=ord(c)<=0xDFFF for c in x),"control characters or surrogate codepoints outside canonical profile")
        if isinstance(x,dict):
            for key,y in x.items():walk(key);walk(y)
        elif isinstance(x,list):
            for y in x:walk(y)
    walk(v);return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def md(raw,role,now,floor,allow_expired=False):
    doc=load(raw);fields(doc,['signed','signatures']);signed=obj(doc['signed']);need(signed.get('_type')==role,"metadata role mismatch")
    import re
    need(re.fullmatch(r'1[.][0-9]+[.][0-9]+',string(signed.get('spec_version'),32)) is not None,"only string TUF 1.x semver supported")
    need(re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',string(signed.get('expires'),32)) is not None,"metadata expiry requires TUF UTC seconds format")
    instant(signed['expires'])
    integer(signed.get('version'),1);need(signed['version']>=floor,"metadata version rollback")
    if not allow_expired:need(instant(signed.get('expires'))>now,"metadata expired")
    return doc
def root_keys(root):
    s=root['signed'];fields(s,['_type','spec_version','version','expires','keys','roles'],['consistent_snapshot'])
    if 'consistent_snapshot' in s:boolean(s['consistent_snapshot'])
    keys=obj(s['keys']);need(1<=len(keys)<=128,"invalid root key set");out={};fps=set()
    for kid,k in keys.items():
        string(kid,256);fields(k,['keytype','scheme','keyval']);fields(k['keyval'],['public'])
        need(k['keytype']=='ed25519' and k['scheme']=='ed25519',"only Ed25519 TUF keys supported")
        text=string(k['keyval']['public'],64)
        try:raw=bytes.fromhex(text)
        except ValueError:raise ReviewError("invalid TUF public key") from None
        need(len(raw)==32 and len(text)==64 and text==raw.hex(),"noncanonical TUF public key")
        key=valid_public_key(ed25519.Ed25519PublicKey.from_public_bytes(raw));fp=fingerprint(key);need(fp not in fps,"same key under multiple root identities");fps.add(fp);out[kid]=key
    need(set(s['roles'])=={'root','timestamp','snapshot','targets'},"unexpected or missing root roles")
    for role,rule in obj(s['roles']).items():
        fields(rule,['keyids','threshold']);ids=seq(rule['keyids'],128);need(ids and len(ids)==len(set(ids)) and all(k in out for k in ids),"invalid role key identities")
        integer(rule['threshold'],1,len(ids))
    return out
def check_signatures(doc,root,role):
    keys=root_keys(root);rule=root['signed']['roles'][role];allowed=set(rule['keyids']);data=canonical(doc['signed']);seen=set();accepted=set()
    for s in seq(doc['signatures'],128):
        fields(s,['keyid','sig']);kid=string(s['keyid'],256);need(kid not in seen,"duplicate TUF signature key");seen.add(kid)
        text=string(s['sig'],128)
        try:raw=bytes.fromhex(text)
        except ValueError:raise ReviewError("invalid TUF signature encoding") from None
        need(len(raw)==64 and text==raw.hex(),"invalid TUF signature length or encoding")
        if kid in allowed:
            try:valid_public_key(keys[kid]);valid_ed_signature(raw);keys[kid].verify(raw,data);accepted.add(kid)
            except InvalidSignature:raise ReviewError("TUF signature mismatch") from None
    need(len(accepted)>=rule['threshold'],"TUF signature threshold unmet")
def bind(info,raw,version):
    fields(info,['version','length','hashes']);need(integer(info['version'],1)==version,"metadata linkage version mismatch")
    need(integer(info['length'],0,4194304)==len(raw),"metadata linkage length mismatch")
    fields(info['hashes'],['sha256']);need(info['hashes']['sha256']==hashlib.sha256(raw).hexdigest(),"metadata linkage SHA-256 mismatch")
def audit(d):
    fields(d,['trusted_root','trusted_root_sha256','root_updates','timestamp','snapshot','targets','prior_versions','target_files','now'])
    now=instant(d['now']);floors=obj(d['prior_versions']);fields(floors,['root','timestamp','snapshot','targets']);floors={r:integer(v,0) for r,v in floors.items()}
    raw=b64(d['trusted_root']);need(hashlib.sha256(raw).hexdigest()==string(d['trusted_root_sha256'],64),"pinned root digest mismatch")
    root=md(raw,'root',now,floors['root'],True);check_signatures(root,root,'root')
    updates=seq(d['root_updates'],32)
    for encoded in updates:
        newer=md(b64(encoded),'root',now,root['signed']['version']+1,True);need(newer['signed']['version']==root['signed']['version']+1,"root versions must be sequential")
        check_signatures(newer,root,'root');check_signatures(newer,newer,'root');root=newer
    need(instant(root['signed']['expires'])>now,"final root expired")
    docs={};raws={}
    for role in ('timestamp','snapshot','targets'):
        raws[role]=b64(d[role]);docs[role]=md(raws[role],role,now,floors[role]);check_signatures(docs[role],root,role)
    ts=docs['timestamp']['signed'];fields(ts,['_type','spec_version','version','expires','meta']);fields(ts['meta'],['snapshot.json'])
    sn=docs['snapshot']['signed'];fields(sn,['_type','spec_version','version','expires','meta']);fields(sn['meta'],['targets.json'])
    targets=docs['targets']['signed'];fields(targets,['_type','spec_version','version','expires','targets']);declared=obj(targets['targets']);need(len(declared)<=1024,"target count limit")
    bind(ts['meta']['snapshot.json'],raws['snapshot'],sn['version']);bind(sn['meta']['targets.json'],raws['targets'],targets['version'])
    files=obj(d['target_files']);need(set(files)==set(declared),"every target must have supplied local bytes")
    checked=[]
    for path,info in declared.items():
        string(path,4096);p=PurePosixPath(path);need(path and not p.is_absolute() and '..' not in p.parts and chr(92) not in path and str(p)==path,"unsafe or noncanonical target name")
        fields(info,['length','hashes']);fields(info['hashes'],['sha256']);data=b64(files[path]);need(integer(info['length'],0,4194304)==len(data) and info['hashes']['sha256']==hashlib.sha256(data).hexdigest(),"target length or digest mismatch")
        checked.append({'target_name_sha256':hashlib.sha256(path.encode()).hexdigest(),'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)})
    return report(verified=True,profile='TUF 1.x Ed25519 traditional top-level strict hash profile',versions={'root':root['signed']['version'],**{r:docs[r]['signed']['version'] for r in docs}},targets=checked,persistent_state_updated=False)
