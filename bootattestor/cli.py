from __future__ import annotations
import argparse, sys
from .version import get_version
from .attestor import run_attest, create_baseline, save_baseline, export_sbom
from .errors import AttestorError

def _parser()->argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='bootattest')
    sub = p.add_subparsers(dest='cmd', required=True)

    att = sub.add_parser('attest', help='run attestation')
    att.add_argument('--event-log', help='path to TCG event log')
    att.add_argument('--efivars', help='path to efivars directory')
    att.add_argument('--baseline', required=True, help='baseline json path')
    att.add_argument('--policy', help='policy json with PCR severities')
    att.add_argument('--format', choices=['text','json','sarif','junit'], default='text')
    att.add_argument('--output', help='write report to file')
    att.add_argument('--fail-on', choices=['none','low','medium','high','critical'], default='medium')

    bl = sub.add_parser('baseline', help='baseline operations')
    bl_sub = bl.add_subparsers(dest='bcmd', required=True)
    blc = bl_sub.add_parser('create', help='create baseline')
    blc.add_argument('--event-log', help='path to TCG event log')
    blc.add_argument('--efivars', help='path to efivars directory')
    blc.add_argument('-o','--output', required=True)

    sb = sub.add_parser('sbom', help='export boot SBOM')
    sb.add_argument('--event-log', help='path to TCG event log')
    sb.add_argument('--efivars', help='path to efivars directory')
    sb.add_argument('-o','--output', required=True)

    sub.add_parser('version', help='print version')
    return p

def main(argv: list[str] | None = None)->int:
    args = _parser().parse_args(argv)
    try:
        if args.cmd == 'attest':
            return run_attest(args.event_log, args.baseline, args.efivars, args.format, args.output, args.fail_on, args.policy)
        if args.cmd == 'baseline' and args.bcmd == 'create':
            bl = create_baseline(args.event_log, args.efivars, None)
            save_baseline(bl, args.output)
            print(f'Wrote baseline to {args.output}')
            return 0
        if args.cmd == 'sbom':
            export_sbom(args.event_log, args.efivars, args.output)
            print(f'Wrote SBOM to {args.output}')
            return 0
        if args.cmd == 'version':
            print(get_version()); return 0
        return 2
    except AttestorError as e:
        print(f'error: {e}', file=sys.stderr); return 2
