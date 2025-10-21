import pytest
from bootattestor.tcg import parse_tpm2_eventlog
from bootattestor.errors import AttestorError

def test_truncated_log_raises():
    with pytest.raises(AttestorError): parse_tpm2_eventlog(b'short')

def test_bad_digest_count():
    bogus = (0).to_bytes(4,'little') + (3).to_bytes(4,'little') + (100).to_bytes(4,'little') + b'\x00'*100
    with pytest.raises(AttestorError): parse_tpm2_eventlog(bogus)
