"""Offline cache, durable event delivery, migration and recovery tests."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cached_plugin', ROOT / 'check_certspotter.py')
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

def options(**kwargs):
    result = dict(poll_interval=21600, warning_duration=3600, timeout=1, max_queries=8)
    result.update(kwargs)
    return SimpleNamespace(**result)

def ready():
    state = plugin.new_state(['example.com'])
    state['domains']['example.com'] = dict(cursor='10', initialized=True)
    return state

class CachedMonitorTests(unittest.TestCase):
    def test_hourly_expiry_does_not_query_or_move_cursor(self):
        state = ready()
        fetch = mock.Mock(side_effect=[[{'id': '11', 'dns_names': ['www.example.com']}], []])
        code, output, active = plugin.evaluate(['example.com'], state, 'token', options(), 10000, fetch)
        self.assertEqual(code, plugin.WARNING)
        active[0]['announced_at'] = 10000
        for now, expected in [(13599, plugin.WARNING), (13600, plugin.OK), (31599, plugin.OK)]:
            code, output, active = plugin.evaluate(['example.com'], state, 'token', options(), now, fetch)
            self.assertEqual(code, expected)
            self.assertIn('API cached', output)
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(state['domains']['example.com']['cursor'], '11')
        self.assertEqual(len(state['events']), 1)
        fetch.side_effect = None
        fetch.return_value = []
        plugin.evaluate(['example.com'], state, 'token', options(), 31600, fetch)
        self.assertEqual(fetch.call_count, 3)

    def test_api_error_stays_unknown_without_hourly_retries(self):
        state = ready()
        fetch = mock.Mock(side_effect=plugin.CheckError('HTTP 429'))
        for now in [10000, 13600, 20000]:
            code, output, active = plugin.evaluate(['example.com'], state, 'token', options(), now, fetch)
            self.assertEqual(code, plugin.UNKNOWN)
            self.assertIn('HTTP 429', output)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(state['domains']['example.com']['cursor'], '10')
        self.assertIsNone(state['last_success'])

    def test_backlog_resumes_and_does_not_discard_partial_findings(self):
        state = ready()
        fetch = mock.Mock(return_value=[{'id': '11'}])
        code, output, active = plugin.evaluate(['example.com'], state, 'token', options(max_queries=1), 10000, fetch)
        self.assertEqual(code, plugin.WARNING)
        self.assertIn('pagination incomplete', output)
        active[0]['announced_at'] = 10000
        code, output, active = plugin.evaluate(['example.com'], state, 'token', options(max_queries=1), 13600, fetch)
        self.assertEqual(code, plugin.UNKNOWN)
        fetch.side_effect = [[{'id': '12'}], []]
        plugin.evaluate(['example.com'], state, 'token', options(), 31600, fetch)
        self.assertEqual(fetch.call_args_list[-2].args[1], '11')
        self.assertEqual([e['issuance']['id'] for e in state['events']], ['11', '12'])

    def test_missing_state_requires_explicit_initialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state.json'
            with self.assertRaisesRegex(plugin.CheckError, 'state is missing'):
                plugin.load_state(path, ['example.com'])
            state = plugin.load_state(path, ['example.com'], initialize=True)
            self.assertFalse(state['domains']['example.com']['initialized'])

    def test_v1_migration_keeps_cursor_and_requires_explicit_new_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state.json'
            old = {'version': 1, 'domains': {'example.com': {'cursor': '123', 'initialized': True}}}
            path.write_text(json.dumps(old))
            state = plugin.load_state(path, ['example.com'])
            self.assertEqual(state['version'], 2)
            self.assertEqual(state['domains'], old['domains'])
            with self.assertRaisesRegex(plugin.CheckError, 'no cursor state'):
                plugin.load_state(path, ['example.com', 'example.net'])
            added = plugin.load_state(path, ['example.com', 'example.net'], True)
            self.assertEqual(added['domains']['example.com']['cursor'], '123')

    def test_unannounced_event_replays_after_restart_even_when_old(self):
        state = ready()
        plugin.evaluate(['example.com'], state, 'token', options(), 10000,
                        mock.Mock(side_effect=[[{'id': '11'}], []]))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state.json'
            plugin.save_state(path, state)
            recovered = plugin.load_state(path, ['example.com'])
        code, output, active = plugin.evaluate(['example.com'], recovered, 'token', options(), 18000,
                                               mock.Mock(side_effect=AssertionError('no API')))
        self.assertEqual(code, plugin.WARNING)
        self.assertIn('issuance 11', output)
        self.assertIsNone(active[0]['announced_at'])

    def test_truncated_output_keeps_all_full_events(self):
        state = ready()
        page = [{'id': str(i), 'dns_names': [f'long-name-{i}.example.com'] * 12} for i in range(11, 70)]
        code, output, active = plugin.evaluate(['example.com'], state, 'token', options(), 10000,
                                              mock.Mock(side_effect=[page, []]))
        self.assertEqual(code, plugin.WARNING)
        self.assertIn('truncated', output)
        self.assertEqual([e['issuance'] for e in state['events']], page)

    def test_corrupt_history_is_not_silently_cleared(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state.json'
            state = ready()
            state['events'] = [{'domain': 'example.com', 'issuance': {'id': '11'}}]
            path.write_text(json.dumps(state))
            with self.assertRaises(plugin.CheckError):
                plugin.load_state(path, ['example.com'])

    def test_polling_attempts_include_failures_in_query_budget(self):
        state = plugin.new_state(['example.com', 'example.net'])
        fetch = mock.Mock(side_effect=plugin.CheckError('HTTP 500'))
        findings, errors, queries = plugin.poll(['example.com', 'example.net'], state, 'token', 1, 2, fetch)
        self.assertEqual(queries, 2)
        self.assertEqual(fetch.call_count, 2)

    def test_non_advancing_cursor_is_unknown(self):
        findings, errors, queries = plugin.poll(['example.com'], ready(), 'token', 1, 8,
                                                mock.Mock(return_value=[{'id': '10'}]))
        self.assertFalse(findings)
        self.assertIn('non-advancing', errors[0])

    def test_cli_failed_delivery_keeps_event_pending_and_cache_limits_queries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state.json'
            plugin.save_state(path, ready())
            args = plugin.build_parser().parse_args(['--domain', 'example.com', '--state-file', str(path)])
            fetch = mock.Mock(side_effect=[[{'id': '11'}], []])
            real_evaluate = plugin.evaluate
            def evaluate(*values, **kwargs):
                return real_evaluate(*values, now=10000, fetch=fetch)
            with mock.patch.object(plugin, 'build_parser') as parser, \
                 mock.patch.object(plugin, 'load_token', return_value='token'), \
                 mock.patch.object(plugin, 'evaluate', side_effect=evaluate), \
                 mock.patch('builtins.print', side_effect=BrokenPipeError):
                parser.return_value.parse_args.return_value = args
                self.assertEqual(plugin.main(), plugin.UNKNOWN)
            stored = plugin.load_state(path, ['example.com'])
            self.assertEqual(stored['domains']['example.com']['cursor'], '11')
            self.assertIsNone(stored['events'][0]['announced_at'])
            with mock.patch.object(plugin, 'build_parser') as parser, \
                 mock.patch.object(plugin, 'load_token', return_value='token'), \
                 mock.patch.object(plugin, 'evaluate', side_effect=evaluate), \
                 mock.patch.object(plugin.time, 'time', return_value=10000), \
                 contextlib.redirect_stdout(io.StringIO()):
                parser.return_value.parse_args.return_value = args
                self.assertEqual(plugin.main(), plugin.WARNING)
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(plugin.load_state(path, ['example.com'])['events'][0]['announced_at'], 10000)

    def test_failed_state_write_does_not_emit_success_or_acknowledge_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state.json'
            plugin.save_state(path, ready())
            before = path.read_bytes()
            args = plugin.build_parser().parse_args(['--domain', 'example.com', '--state-file', str(path)])
            def evaluate(domains, state, token, args, now=None):
                state['domains']['example.com']['cursor'] = '11'
                return plugin.WARNING, 'new issuance', []
            capture = io.StringIO()
            with mock.patch.object(plugin, 'build_parser') as parser, \
                 mock.patch.object(plugin, 'load_token', return_value='token'), \
                 mock.patch.object(plugin, 'evaluate', side_effect=evaluate), \
                 mock.patch.object(plugin, 'save_state', side_effect=OSError('disk full')), \
                 contextlib.redirect_stdout(capture):
                parser.return_value.parse_args.return_value = args
                self.assertEqual(plugin.main(), plugin.UNKNOWN)
            self.assertNotIn('new issuance', capture.getvalue())
            self.assertEqual(path.read_bytes(), before)

    def test_show_events_never_reads_token_or_queries_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state.json'
            plugin.save_state(path, ready())
            args = plugin.build_parser().parse_args(['--domain', 'example.com', '--state-file', str(path), '--show-events'])
            capture = io.StringIO()
            with mock.patch.object(plugin, 'build_parser') as parser, \
                 mock.patch.object(plugin, 'load_token', side_effect=AssertionError('must be offline')), \
                 contextlib.redirect_stdout(capture):
                parser.return_value.parse_args.return_value = args
                self.assertEqual(plugin.main(), plugin.OK)
            self.assertEqual(json.loads(capture.getvalue()), [])
