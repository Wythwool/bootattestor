from __future__ import annotations
import hashlib
from typing import Dict, Iterable

ALG_ID_TO_NAME = {0x0004:'sha1',0x000B:'sha256',0x000C:'sha384',0x000D:'sha512',0x0012:'sm3_256'}

def _h(alg:int):
    name = ALG_ID_TO_NAME.get(alg, '')
    if name == 'sha1': return hashlib.sha1
    if name == 'sha256': return hashlib.sha256
    if name == 'sha384': return hashlib.sha384
    if name == 'sha512': return hashlib.sha512
    return None

def compute_pcrs(algs: Dict[int,int], events: Iterable)->Dict[str, Dict[int,str]]:
    state: Dict[int, Dict[int, bytes]] = {}
    for alg in algs:
        hf = _h(alg)
        if hf is None: continue
        state[alg] = {i: b'\x00'*hf().digest_size for i in range(24)}
    for ev in events:
        for alg, dig in ev.digests.items():
            hf = _h(alg)
            if hf is None: continue
            p = state[alg][ev.pcr_index]
            x = hf(); x.update(p); x.update(dig)
            state[alg][ev.pcr_index] = x.digest()
    out: Dict[str, Dict[int,str]] = {}
    for alg, bank in state.items():
        name = ALG_ID_TO_NAME.get(alg, f'alg{alg}')
        out[name] = {i: bank[i].hex() for i in sorted(bank)}
    return out
