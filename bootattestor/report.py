from __future__ import annotations
import json, xml.etree.ElementTree as ET
from typing import List
from .attestor import Finding

def render_text(findings: List[Finding])->str:
    if not findings: return 'OK: no mismatches'
    lines = [f'{f.severity.upper()} {f.kind} {f.id} - {f.message}' for f in findings]
    lines.append(f'Total: {len(findings)}')
    return '\n'.join(lines)

def render_json(findings: List[Finding])->str:
    data = {'version':1,'$schema':'schema://bootattestor/findings.json','findings':[f.__dict__ for f in findings],'summary':{'total':len(findings)}}
    return json.dumps(data, indent=2)

def render_sarif(findings: List[Finding])->str:
    def lvl(s:str)->str:
        return 'error' if s in ('high','critical') else 'warning' if s=='medium' else 'note'
    rules, results = {}, []
    for f in findings:
        rid = f.kind
        if rid not in rules: rules[rid] = {'id':rid,'name':rid,'shortDescription':{'text':rid}}
        results.append({'ruleId':rid,'level':lvl(f.severity),'message':{'text':f'{f.id}: {f.message}'}})
    sarif = {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'bootattestor','rules':list(rules.values())}},'results':results}]}
    return json.dumps(sarif, indent=2)

def render_junit(findings: List[Finding], fail_on: str)->str:
    rank = {'info':1,'low':2,'medium':3,'high':4,'critical':5}
    thr = rank.get(fail_on, 3)
    suite = ET.Element('testsuite', name='bootattestor', tests=str(max(1,len(findings))))
    if not findings:
        ET.SubElement(suite, 'testcase', classname='attestation', name='baseline')
    else:
        for f in findings:
            case = ET.SubElement(suite, 'testcase', classname=f.kind, name=f.id)
            if rank.get(f.severity,1) >= thr:
                fail = ET.SubElement(case, 'failure', message=f.message); fail.text = f'{f.kind}:{f.id}:{f.severity}'
    return ET.tostring(suite, encoding='unicode')
