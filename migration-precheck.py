#!/usr/bin/env python3
"""Read-only report before planning a single-node to three-gateway migration.

Uses only the standard library. Does not read secrets.json, print journals,
change services, create backups, or modify the saved deployment.
"""
import argparse
import json
from pathlib import Path
import re
import ssl
import subprocess
import urllib.error
import urllib.request

CONFIG = Path('/var/lib/litellm-cluster/cluster.json')
STATE = Path('/srv/litellm/installer-state.json')
CA = Path('/var/lib/litellm-cluster/ca.crt')


def hostname(value):
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', value) else '[unset or invalid]'


def number(value):
    return value if type(value) is int else None


def choice(value, allowed):
    return value if isinstance(value, str) and value in allowed else 'unknown'


def public_plan(plan):
    """Explicitly select nested fields; never dump entire plan/state objects."""
    services, gateway, answers = plan.get('services', {}), plan.get('gateway', {}), plan.get('answers', {})
    return {
        'nodes': [{'name': hostname(n.get('name')), 'address': hostname(n.get('address')),
                   'interface': hostname(n.get('interface'))} for n in plan.get('nodes', [])],
        'datastores': plan.get('datastores', 'replicated' if len(plan.get('nodes', [])) == 3 else 'local')
            if plan.get('datastores', 'ha') in ('ha', 'node1') else 'unknown',
        'services': {'postgresql': choice(services.get('postgresql'), ('managed', 'external')),
                     'redis': choice(services.get('redis'), ('managed', 'external')),
                     'haproxy': services.get('haproxy') is True, 'vip_enabled': bool(services.get('vip'))},
        'gateway': {'mode': choice(gateway.get('mode'), ('container', 'native')),
                    'workers': number(gateway.get('workers')),
                    'version': gateway.get('version') if re.fullmatch(r'v\d+\.\d+\.\d+', str(gateway.get('version', ''))) else 'unknown'},
        'fqdn': hostname(answers.get('fqdn')),
        'pg_host': hostname(answers.get('pg_host')), 'pg_port': number(answers.get('pg_port')),
        'redis_topology': choice(answers.get('redis_topology'), ('standalone', 'sentinel', 'cluster')),
        'redis_nodes': [[hostname(endpoint[0]), number(endpoint[1])] for endpoint in answers.get('redis_nodes', [])],
    }


def service_status(name, user=False):
    argv = ['systemctl'] + (['--user', '-M', 'litellm@'] if user else []) + ['is-active', name]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        # Never include arbitrary stderr or process output in the shareable report.
        return choice(result.stdout.strip(), ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading', 'unknown'))
    except (OSError, subprocess.TimeoutExpired):
        return 'unavailable'


def readiness():
    if not CA.is_file():
        return {'result': 'not checked', 'reason': 'Installer CA not found'}
    try:
        ctx = ssl.create_default_context(cafile=str(CA))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
        with opener.open('https://127.0.0.1:4000/health/readiness', timeout=5) as response:
            return {'http_status': response.status, 'result': 'ready' if response.status == 200 else 'not ready'}
    except urllib.error.HTTPError as exc:
        return {'http_status': exc.code, 'result': 'not ready'}
    except (OSError, ValueError):
        return {'result': 'not ready', 'reason': 'Connection or certificate validation failed; inspect installer status locally'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=CONFIG, help='Public cluster plan to inspect')
    parser.add_argument('--state', type=Path, default=STATE, help='Installer state; only runtime mode is selected')
    parser.add_argument('--plan-only', action='store_true', help='Skip local service and HTTPS checks')
    args = parser.parse_args(argv)
    try:
        plan = json.loads(args.config.read_text())
        report = public_plan(plan)
        if not args.plan_only:
            state = json.loads(args.state.read_text()) if args.state.is_file() else {}
            mode = choice(state.get('mode', plan.get('gateway', {}).get('mode')), ('native', 'container'))
            report['runtime_mode'] = mode
            report['gateway_service'] = service_status('litellm', user=mode == 'container') if mode != 'unknown' else 'not checked'
            report['infrastructure_services'] = {name: service_status(name) for name in ('litellm-postgres', 'litellm-redis', 'litellm-haproxy')}
            report['local_readiness'] = readiness()
        print(json.dumps(report, indent=2))
        print('\nReport only. No migration or configuration changes performed.')
        print('A saved single-node deployment requires a planned migration; do not edit its node list and Resume.')
        return 0
    except PermissionError:
        print('Cannot read the saved plan/state. Run this precheck with sudo.')
    except FileNotFoundError:
        print('Saved plan not found. Supply --config /path/to/cluster.json if it is stored elsewhere.')
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError):
        # Do not echo malformed input values or JSON excerpts containing credentials.
        print('Cannot parse the saved plan/state. Inspect its format locally; no files were changed.')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
