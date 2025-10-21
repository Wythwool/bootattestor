from __future__ import annotations
import os, sys, uuid, ctypes
from typing import Dict, Tuple, Any
from .errors import AttestorError

EFI_GLOBAL = uuid.UUID('8BE4DF61-93CA-11d2-AA0D-00E098032B8C')

def _linux_read_efivars(root: str = '/sys/firmware/efi/efivars')->Dict[Tuple[str,str], Dict[str,Any]]:
    out: Dict[Tuple[str,str], Dict[str,Any]] = {}
    if not os.path.isdir(root):
        return out
    for fn in os.listdir(root):
        if '-' not in fn: continue
        name, guid = fn.rsplit('-', 1)
        try:
            g = str(uuid.UUID(guid))
        except Exception:
            continue
        p = os.path.join(root, fn)
        with open(p, 'rb') as f:
            data = f.read()
        attrs = int.from_bytes(data[:4], 'little')
        out[(name, g)] = {'data': data[4:], 'attrs': attrs}
    return out

def _win_read_efivar(name: str, guid: uuid.UUID)->Dict[str,Any] | None:
    k32 = ctypes.windll.kernel32
    GetFirmwareEnvironmentVariableExW = k32.GetFirmwareEnvironmentVariableExW
    GetFirmwareEnvironmentVariableExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    GetFirmwareEnvironmentVariableExW.restype = ctypes.c_uint32
    buf = ctypes.create_string_buffer(65536)
    attrs = ctypes.c_uint32(0)
    r = GetFirmwareEnvironmentVariableExW(name, '{'+str(guid).upper()+'}', buf, ctypes.sizeof(buf), ctypes.byref(attrs))
    if r == 0:
        err = ctypes.GetLastError()
        if err in (2, 203, 1314, 1):  # not found / envvar not found / privilege / invalid function
            return None
        raise AttestorError(f'GetFirmwareEnvironmentVariableExW failed name={name} err={err}')
    return {'data': buf.raw[:r], 'attrs': int(attrs.value)}

def _windows_read_efivars()->Dict[Tuple[str,str], Dict[str,Any]]:
    out: Dict[Tuple[str,str], Dict[str,Any]] = {}
    names = ['SecureBoot','PK','KEK','db','dbx','BootOrder']
    for n in names:
        res = _win_read_efivar(n, EFI_GLOBAL)
        if res: out[(n, str(EFI_GLOBAL))] = res
    for num in range(0, 0x1000):
        n = f'Boot{num:04X}'
        res = _win_read_efivar(n, EFI_GLOBAL)
        if res: out[(n, str(EFI_GLOBAL))] = res
    return out

def load_efivars_meta(override_dir: str | None = None)->Dict[Tuple[str,str], Dict[str,Any]]:
    if override_dir:
        return _linux_read_efivars(override_dir)
    if sys.platform.startswith('linux'):
        return _linux_read_efivars()
    if sys.platform == 'win32':
        return _windows_read_efivars()
    return {}

def load_efivars(override_dir: str | None = None)->Dict[Tuple[str,str], bytes]:
    meta = load_efivars_meta(override_dir)
    return {k: v['data'] for k,v in meta.items()}
