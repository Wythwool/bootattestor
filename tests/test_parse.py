from bootattestor.tcg import parse_tpm2_eventlog
from bootattestor.pcr import compute_pcrs

def test_parse_and_compute():
    blob = open('tests/fixtures_eventlog_tpm2.bin','rb').read()
    algs, events = parse_tpm2_eventlog(blob)
    assert 0x000B in algs and 0x0004 in algs
    assert any(e.pcr_index == 7 for e in events)
    pcrs = compute_pcrs(algs, events)
    assert 'sha256' in pcrs and 7 in pcrs['sha256']
