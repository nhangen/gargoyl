"""Real private-pipe parsing with fake session execution; never opens Keychain/network."""

import json
import os
import sys
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

from gargoyl.gui_runtime import main


class RestorePipeTests(unittest.TestCase):
    def execute(self, raw):
        incoming, writer = os.pipe()
        outgoing, output = os.pipe()
        os.write(writer, raw)
        os.close(writer)
        run = Mock()
        with ExitStack() as stack:
            stdin = stack.enter_context(os.fdopen(incoming, "r", encoding="utf-8"))
            stdout = stack.enter_context(os.fdopen(output, "w", encoding="utf-8"))
            stack.enter_context(patch.object(sys, "stdin", stdin))
            stack.enter_context(patch.object(sys, "stdout", stdout))
            stack.enter_context(
                patch.object(sys, "argv", ["gargoyl.gui_runtime", "fleet-restore"])
            )
            stack.enter_context(
                patch("gargoyl.gui_runtime.console_owner", return_value=True)
            )
            stack.enter_context(
                patch("gargoyl.gui_runtime.os.getuid", return_value=501)
            )
            stack.enter_context(
                patch("gargoyl.gui_runtime.owner_home", return_value=Path("/owner"))
            )
            stack.enter_context(patch("gargoyl.fleet_session.run_session", run))
            result = main()
        with os.fdopen(outgoing, "rb") as reader:
            emitted = reader.read()
        return result, run, emitted

    def test_saved_scope_and_original_expiry_enter_only_the_session(self):
        expiry = time.time() + 100
        request = dict(
            purpose="desktop_account",
            token="darkbloom-at-private-fixture-token",
            valid_until=expiry,
        )
        result, run, emitted = self.execute(json.dumps(request).encode() + b"\n")
        self.assertEqual(result, 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["initial_token"], request["token"])
        self.assertFalse(run.call_args.kwargs["remember"])
        self.assertLessEqual(run.call_args.kwargs["session_seconds"], 100)
        self.assertGreater(run.call_args.kwargs["session_seconds"], 95)
        self.assertNotIn(b"private-fixture-token", emitted)

    def test_broad_duplicate_expired_and_extra_frames_never_start_session(self):
        valid = dict(
            purpose="desktop_account",
            token="darkbloom-at-private-fixture-token",
            valid_until=time.time() + 100,
        )
        requests = [
            json.dumps(dict(valid, purpose="provider")).encode() + b"\n",
            json.dumps(dict(valid, token="eigeninference-pt-broad")).encode() + b"\n",
            json.dumps(dict(valid, valid_until=time.time() - 1)).encode() + b"\n",
            json.dumps(dict(valid, valid_until=True)).encode() + b"\n",
            json.dumps(valid).encode() + b"\n{}\n",
            b'{"purpose":"provider","purpose":"desktop_account","token":"darkbloom-at-private-fixture-token","valid_until":9999999999}\n',
        ]
        for raw in requests:
            result, run, emitted = self.execute(raw)
            self.assertEqual(result, 1)
            run.assert_not_called()
            self.assertNotIn(b"private-fixture-token", emitted)
            self.assertNotIn(b"eigeninference", emitted)
