from __future__ import annotations
import os, sys, json, hashlib, re
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Tuple
from importlib import resources
from jsonschema import validate as jsonschema_validate, ValidationError

from .tcg import parse_tpm2_eventlog, EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_BOOT_SERVICES_DRIVER, EV_EFI_RUNTIME_SERVICES_DRIVER
from .pcr import compute_pcrs
from .efivars import load_efivars, load_efivars_meta
from .errors import AttestorError
from .report import render_text, render_json, render_sarif, render_junit

@dataclass
class Baseline:
    schema_version: int
    platform: str
    digests: Dict[str, Dict[int, str]]
    variables: Dict[str, str]
    created_at: int

@dataclass
class Finding:
    kind: str
    id: str
    severity: str
    message: str

def _auto_eventlog_path()->str | None:
    for p in ['/sys/kernel/security/tpm0/binary_bios_measurements','/sys/kernel/security/tpm1/binary_bios_measurements','/sys/firmware/tpm/tpm0/binary_bios_measurements','/sys/firmware/tpm/tpm1/binary_bios_measurements']:
        if os.path.exists(p): return p
    return None

def load_event_log(path: str | None = None)->bytes:
    p = path or _auto_eventlog_path()
    if not p or not os.path.exists(p): raise AttestorError('event log not found; pass --event-log')
    return open(p,'rb').read()

def load_efivars(path: str | None = None):
    from .efivars import load_efivars as _lf
    return _lf(path)

def _hash_vars(vars: Dict[Tuple[str,str], bytes])->Dict[str,str]:
    return { f'{name}-{guid}': hashlib.sha256(data).hexdigest() for (name,guid), data in vars.items() }

def _baseline_schema()->dict:
    return json.loads(resources.read_text('bootattestor.schemas','baseline.schema.json'))

def _validate_baseline_dict(obj: dict)->None:
    try:
        jsonschema_validate(obj, _baseline_schema())
    except ValidationError as e:
        raise AttestorError(f'baseline schema validation failed: {e.message}')

def load_policy(policy_path: str | None)->Dict[str, List[int]]:
    if not policy_path: return {'critical':[7], 'high':[0,2,4,5], 'medium':[], 'low':[]}
    data = json.load(open(policy_path,'r',encoding='utf-8'))
    if not isinstance(data, dict): raise AttestorError('policy must be a JSON object with severity arrays')
    return data

def _sev_for_pcr(idx: int, policy: Dict[str, List[int]])->str:
    if idx in policy.get('critical',[7]): return 'critical'
    if idx in policy.get('high',[0,2,4,5]): return 'high'
    if idx in policy.get('medium',[]): return 'medium'
    return 'low'

def create_baseline(event_log_path: str | None, efivars_dir: str | None, platform: str | None = None)->Baseline:
    blob = load_event_log(event_log_path)
    algs, events = parse_tpm2_eventlog(blob)
    pcrs = compute_pcrs(algs, events)
    vars_raw = load_efivars(efivars_dir)
    return Baseline(schema_version=1, platform=platform or ('windows' if sys.platform=='win32' else 'linux'), digests=pcrs, variables=_hash_vars(vars_raw), created_at=int(__import__('time').time()))

def diff_attestation(baseline: Baseline, event_blob: bytes, efivars_dir: str | None, policy: Dict[str,List[int]])->List[Finding]:
    algs, events = parse_tpm2_eventlog(event_blob)
    pcrs_now = compute_pcrs(algs, events)
    vars_now = _hash_vars(load_efivars(efivars_dir))
    finds: List[Finding] = []
    for bank in baseline.digests.keys():
        if bank not in pcrs_now:
            finds.append(Finding('bank-missing', bank, 'high', f'bank {bank} not present in event log'))
    for bank, pmap in baseline.digests.items():
        cur_bank = pcrs_now.get(bank, {})
        for idx_s, exp_hex in pmap.items():
            idx = int(idx_s)
            got_hex = cur_bank.get(idx)
            if got_hex is None or got_hex.lower() != exp_hex.lower():
                finds.append(Finding('pcr-mismatch', f'PCR{idx}.{bank}', _sev_for_pcr(idx, policy), f'expected {exp_hex}, got {got_hex or 'missing'}'))
    for k, exp in baseline.variables.items():
        got = vars_now.get(k)
        if got is None or got.lower() != exp.lower():
            finds.append(Finding('var-mismatch', k, 'high', f'variable changed: expected {exp}, got {got or 'missing'}'))
    return finds

def save_baseline(bl: Baseline, path: str)->None:
    obj = asdict(bl); obj['$schema'] = 'schema://bootattestor/baseline.json'
    _validate_baseline_dict(obj)
    with open(path,'w',encoding='utf-8') as f: json.dump(obj, f, indent=2)

def run_attest(event_log_path: str | None, baseline_path: str, efivars_dir: str | None, fmt: str, out_file: str | None, fail_on: str, policy_path: str | None = None)->int:
    base_obj = json.load(open(baseline_path,'r',encoding='utf-8'))
    _validate_baseline_dict(base_obj)
    bl = Baseline(schema_version=base_obj['schema_version'], platform=base_obj['platform'], digests={k:{int(i):v for i,v in d.items()} for k,d in base_obj['digests'].items()}, variables=base_obj['variables'], created_at=base_obj['created_at'])
    policy = load_policy(policy_path)
    blob = load_event_log(event_log_path)
    finds = diff_attestation(bl, blob, efivars_dir, policy)
    if fmt == 'text': content = render_text(finds)
    elif fmt == 'json': content = render_json(finds)
    elif fmt == 'sarif': content = render_sarif(finds)
    elif fmt == 'junit': content = render_junit(finds, fail_on)
    else: raise AttestorError('bad format')
    if out_file:
        os.makedirs(os.path.dirname(out_file) or '.', exist_ok=True)
        with open(out_file,'w',encoding='utf-8') as f: f.write(content)
    else:
        print(content)
    rank = {'info':1,'low':2,'medium':3,'high':4,'critical':5}
    thr = rank.get(fail_on, 3)
    worst = max([rank.get(f.severity,1) for f in finds], default=0)
    return 1 if worst >= thr else 0

def export_sbom(event_log_path: str | None, efivars_dir: str | None, out_file: str)->None:
    blob = load_event_log(event_log_path)
    algs, events = parse_tpm2_eventlog(blob)
    comps: List[Dict[str, Any]] = []
    for ev in events:
        if ev.event_type in (EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_BOOT_SERVICES_DRIVER, EV_EFI_RUNTIME_SERVICES_DRIVER):
            s = ev.data.decode('utf-8', errors='ignore')
            path = ''
            for marker in ('\\EFI\\','/EFI/'):
                if marker in s:
                    start = s.find(marker)
                    end = s.find('.efi', start)
                    if end != -1:
                        path = s[start:end+4]; break
            comps.append({'type':'efi_image','pcr':ev.pcr_index,'path':path,'digests':{f'alg{alg}':dig.hex() for alg,dig in ev.digests.items()}})
    vars_meta = load_efivars_meta(efivars_dir)
    for (name,guid), meta in vars_meta.items():
        comps.append({'type':'uefi_variable','name':name,'guid':guid,'sha256':hashlib.sha256(meta['data']).hexdigest(),'size':len(meta['data']),'attrs':meta['attrs']})
    sbom = {'schema_version':1,'generator':{'name':'bootattestor','version':'0.2.0'},'generated_at':int(__import__('time').time()),'components':comps}
    with open(out_file,'w',encoding='utf-8') as f: json.dump(sbom, f, indent=2)
