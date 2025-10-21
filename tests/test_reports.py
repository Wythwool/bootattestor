from bootattestor.report import render_sarif, render_junit, render_json
from bootattestor.attestor import Finding

def test_reports_and_threshold():
    f = [Finding('pcr-mismatch','PCR7.sha256','critical','mismatch')]
    assert '2.1.0' in render_sarif(f)
    j = render_junit(f, 'critical'); assert '<failure' in j
    js = render_json([]); assert '"total": 0' in js
