from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import Dict, List, Tuple
from .errors import AttestorError

ALG_SHA1    = 0x0004
ALG_SHA256  = 0x000B
ALG_SHA384  = 0x000C
ALG_SHA512  = 0x000D
ALG_SM3_256 = 0x0012

EV_PREBOOT_CERT = 0x00000000
EV_POST_CODE = 0x00000001
EV_NO_ACTION = 0x00000003
EV_SEPARATOR = 0x00000004
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
EV_EFI_VARIABLE_BOOT = 0x80000002
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000006
EV_EFI_BOOT_SERVICES_DRIVER = 0x80000007
EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000008
EV_EFI_GPT_EVENT = 0x80000009
EV_EFI_ACTION = 0x8000000A

ALG_SIZES = {ALG_SHA1:20, ALG_SHA256:32, ALG_SHA384:48, ALG_SHA512:64, ALG_SM3_256:32}

@dataclass
class TcgEvent2:
    pcr_index: int
    event_type: int
    digests: Dict[int, bytes]
    data: bytes

def _require(cond: bool, msg: str)->None:
    if not cond:
        raise AttestorError(msg)

def _parse_specid_struct(data: bytes)->Tuple[Dict[int,int], int]:
    _require(len(data) >= 16, "SpecID too short")
    sig = data[:16]
    _require(sig.startswith(b"Spec ID Event03"), "SpecID signature mismatch")
    off = 16
    _require(len(data) >= off + 8, "SpecID header truncated")
    off += 8
    _require(len(data) >= off + 4, "SpecID alg count missing")
    (num_algs,) = struct.unpack_from("<I", data, off)
    _require(0 < num_algs <= 16, "SpecID alg count invalid")
    off += 4
    algs: Dict[int,int] = {}
    for _ in range(num_algs):
        _require(len(data) >= off + 4, "SpecID alg entry truncated")
        alg, dsz = struct.unpack_from("<HH", data, off)
        _require(dsz in (20,32,48,64), "SpecID digest size invalid")
        algs[alg] = dsz
        off += 4
    _require(len(data) >= off + 1, "SpecID vendor size missing")
    vlen = data[off]
    off += 1 + vlen
    return algs, off

def parse_tpm2_eventlog(blob: bytes)->Tuple[Dict[int,int], List[TcgEvent2]]:
    off = 0
    _require(len(blob) >= 16, "log too small")
    pcr_index, ev_type, digest_count = struct.unpack_from("<III", blob, off)
    off += 12
    _require(ev_type == EV_NO_ACTION, "first event not EV_NO_ACTION/SpecID")
    _require(digest_count <= 16, "digestCount insane")
    for _ in range(digest_count):
        _require(len(blob) >= off + 2, "truncated alg header in SpecID")
        off += 2
        _require(len(blob) >= off + 20, "truncated SpecID digest")
        off += 20
    _require(len(blob) >= off + 4, "SpecID event size missing")
    (event_size,) = struct.unpack_from("<I", blob, off)
    off += 4
    _require(len(blob) >= off + event_size, "SpecID data truncated")
    spec_data = blob[off:off+event_size]
    off += event_size
    algs, _ = _parse_specid_struct(spec_data)

    events: List[TcgEvent2] = []
    while off + 16 <= len(blob):
        pcr_index, ev_type, digest_count = struct.unpack_from("<III", blob, off)
        off += 12
        _require(digest_count <= 16, "digestCount too large")
        digests: Dict[int, bytes] = {}
        for _ in range(digest_count):
            _require(len(blob) >= off + 2, "truncated alg header")
            alg = struct.unpack_from("<H", blob, off)[0]
            off += 2
            dsz = algs.get(alg, ALG_SIZES.get(alg, 0))
            _require(dsz in (20,32,48,64), "unknown digest size")
            _require(len(blob) >= off + dsz, "truncated digest body")
            digests[alg] = blob[off:off+dsz]
            off += dsz
        _require(len(blob) >= off + 4, "event size missing")
        (event_size,) = struct.unpack_from("<I", blob, off)
        off += 4
        _require(len(blob) >= off + event_size, "event data truncated")
        data = blob[off:off+event_size]
        off += event_size
        events.append(TcgEvent2(pcr_index, ev_type, digests, data))
    return algs, events
