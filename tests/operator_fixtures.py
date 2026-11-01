"""A self-authored fake `darkbloom` for operator-tool tests. Never touches a real provider.

The fake prints the exact message strings of Darkbloom 0.10.5/0.10.6 RestartCommand,
ServiceDrain and doctor, chosen by a scenario file, and simulates the provider by
rewriting a private daemon-state file. Each invocation appends to a log so tests can
count real launches.
"""
import json
import os
import sys
import tempfile
import textwrap
import time
from pathlib import Path

HOST = '00000000-0000-4000-8000-000000000001'
OLD = {'pid': 4242, 'born_us': 1_700_000_000_000_000}
NEW = {'pid': 5252, 'born_us': 1_700_000_100_000_000}

FAKE = textwrap.dedent('''\
    #!{python}
    import json, os, sys, time
    here = os.path.dirname(os.path.abspath(__file__))
    scenario = json.load(open(os.path.join(here, 'scenario.json')))
    with open(os.path.join(here, 'calls.log'), 'a') as log:
        log.write(' '.join(sys.argv[1:]) + '\\n')
    def state(identity, status='online'):
        data = dict(schema=1, pid=identity['pid'], version=scenario['state_version'],
                    written_at=time.time(), started_at=time.time() - 5,
                    process_identity=dict(pid=identity['pid'], start_time_micros=identity['born_us']),
                    trust=dict(status=status), stats=dict(requests_served=1, tokens_generated=1),
                    warm_models=[], inference_active=False)
        path = scenario['state']
        temporary = path + '.tmp'
        with open(temporary, 'w') as stream:
            json.dump(data, stream)
        os.replace(temporary, path)
    arguments = sys.argv[1:]
    if arguments == ['--version']:
        print(scenario['version']); sys.exit(0)
    if arguments == ['status']:
        print('darkbloom ' + scenario['version'])
        print('Provider: private-provider-name')
        print('Daemon: running (pid 4242, up 1h05m)')
        sys.exit(0)
    if arguments == ['doctor']:
        print('SECRET-DIAGNOSIS-TEXT')
        print('')
        print('DETAILED CHECKS')
        print('  [PASS] hardware: /Users/private/path')
        print('  [WARN] model: private-model-name')
        print('  [INFO] cache: ok')
        if scenario.get('doctor_fail'):
            print('  [FAIL] trust: offline')
        print('')
        sys.exit(1 if scenario.get('doctor_fail') else 0)
    if arguments[:1] == ['restart']:
        time.sleep(scenario.get('delay', 0))
        kind = scenario['restart']
        if kind in ('success', 'unconfirmed', 'drain_incomplete', 'forced'):
            print('Draining accepted requests (deadline: 600s). New work is refused by the running provider.')
            print('  2 accepted request(s) remaining')
            sys.stdout.flush()
            time.sleep(scenario.get('drain_delay', 0))
        if kind == 'forced':
            print('Forced stop: drain acknowledgement unavailable; unfinished work will be interrupted.')
        if kind == 'drain_incomplete':
            print('Error: Drain did not complete: 2 unfinished request(s), coordinator acknowledgement false. '
                  'The service remains draining with automatic restart disabled. Repeat stop/restart to wait again, '
                  'or explicitly pass --force.')
            sys.exit(64)
        if kind == 'refused':
            print('Error: Cannot confirm the running provider identity. No process or recovery setting was changed.')
            sys.exit(64)
        print('  Requests finished; waiting for coordinator usage acknowledgement')
        print('Drain drained: 0 unfinished request(s); coordinator acknowledgement: received.')
        print('Drained provider relaunched; waiting for fresh authorization...')
        sys.stdout.flush()
        if kind in ('success', 'forced'):
            state(scenario['new'])
            print('Provider restarted and freshly authorized (legacy).')
            print('  darkbloom status  Check status')
            sys.exit(0)
        if kind == 'unconfirmed':
            print('Error: Restart launched, but fresh authorization was not confirmed within 180s. The new service is '
                  'still starting; inspect darkbloom status. No second restart was issued.')
            sys.exit(64)
        if kind == 'success_no_change':
            print('Provider restarted and freshly authorized (legacy).')
            sys.exit(0)
    sys.exit(2)
''')


class FakeDarkbloom:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(os.path.realpath(self.temp.name))
        self.bin = root / 'bin'
        self.state_dir = root / 'state'
        self.record_dir = root / 'record'
        for directory in (self.bin, self.state_dir, self.record_dir):
            directory.mkdir(mode=0o700)
        self.executable = str(self.bin / 'darkbloom')
        Path(self.executable).write_text(FAKE.format(python=sys.executable))
        os.chmod(self.executable, 0o755)
        self.state = str(self.state_dir / 'daemon-state.json')
        self.configure()
        self.write_state(OLD)

    def configure(self, **changes):
        scenario = {'version': '0.10.6', 'state_version': '0.10.6', 'restart': 'success',
                    'state': self.state, 'new': NEW}
        scenario.update(changes)
        (self.bin / 'scenario.json').write_text(json.dumps(scenario))

    def write_state(self, identity, *, age=0, version='0.10.6'):
        data = dict(schema=1, pid=identity['pid'], version=version, written_at=time.time() - age,
                    started_at=time.time() - 100,
                    process_identity=dict(pid=identity['pid'], start_time_micros=identity['born_us']),
                    trust=dict(status='online'), stats=dict(requests_served=1, tokens_generated=1),
                    warm_models=[], inference_active=False)
        temporary = self.state + '.tmp'
        Path(temporary).write_text(json.dumps(data))
        os.replace(temporary, self.state)

    def calls(self):
        log = self.bin / 'calls.log'
        return log.read_text().splitlines() if log.exists() else []

    def environment(self):
        return {'HOME': str(self.bin), 'PATH': '/usr/bin:/bin', 'LANG': 'C', 'NO_COLOR': '1', 'TERM': 'dumb'}

    def cleanup(self):
        self.temp.cleanup()


def verifier(*allowed):
    """Stands in for the macOS kernel check: true only for listed (pid, birth) pairs."""
    pairs = {(item['pid'], item['born_us']) for item in allowed}
    return lambda identity: (identity['pid'], identity['born_us']) in pairs
