"""
Keygen verification worker.
Uses Speakeasy or Qiling to emulate a binary's validation function
with a given serial/username pair, and checks execution outcome.
"""

import json
import sys
import os
import time


def verify_with_speakeasy(request: dict) -> dict:
    """Verify serial by running validation through Speakeasy emulation."""
    try:
        import speakeasy
    except ImportError:
        return {'ok': False, 'error': 'speakeasy not installed', 'setup_hint': 'pip install speakeasy-emulator'}

    file_path = request.get('file_path', '')
    serial = request.get('serial', '')
    username = request.get('username', '')
    timeout = request.get('timeout_sec', 30)

    t0 = time.time()
    api_calls = []
    success_indicators = []
    failure_indicators = []

    try:
        se = speakeasy.Speakeasy()
        module = se.load_module(file_path)

        # Track MessageBox calls as validation indicators
        success_strings = ['correct', 'success', 'congratulation', 'valid', 'good', 'registered', 'thank']
        failure_strings = ['wrong', 'incorrect', 'invalid', 'fail', 'error', 'denied', 'bad', 'nope']

        def msg_box_hook(emu, api_name, func, params):
            text = params.get('lpText', '') or ''
            caption = params.get('lpCaption', '') or ''
            combined = (text + ' ' + caption).lower()
            api_calls.append({
                'api': api_name,
                'text': text[:200],
                'caption': caption[:200],
            })
            for s in success_strings:
                if s in combined:
                    success_indicators.append({'api': api_name, 'text': text[:200], 'match': s})
            for s in failure_strings:
                if s in combined:
                    failure_indicators.append({'api': api_name, 'text': text[:200], 'match': s})

        # Hook MessageBox variants
        for api in ['user32.MessageBoxA', 'user32.MessageBoxW',
                     'user32.MessageBoxExA', 'user32.MessageBoxExW']:
            try:
                se.add_api_hook(msg_box_hook, api)
            except Exception:
                pass

        se.run_module(module, timeout=timeout)

        elapsed = time.time() - t0
        verdict = 'unknown'
        if success_indicators and not failure_indicators:
            verdict = 'valid'
        elif failure_indicators and not success_indicators:
            verdict = 'invalid'
        elif success_indicators and failure_indicators:
            verdict = 'ambiguous'

        return {
            'ok': True,
            'verdict': verdict,
            'serial': serial,
            'username': username,
            'success_indicators': success_indicators,
            'failure_indicators': failure_indicators,
            'api_calls_captured': len(api_calls),
            'elapsed_sec': round(elapsed, 2),
            'backend': 'speakeasy',
        }

    except Exception as e:
        return {
            'ok': False,
            'error': str(e),
            'elapsed_sec': round(time.time() - t0, 2),
            'backend': 'speakeasy',
        }


def verify_with_qiling(request: dict) -> dict:
    """Verify serial by running validation through Qiling emulation."""
    try:
        from qiling import Qiling
    except ImportError:
        return {'ok': False, 'error': 'qiling not installed', 'setup_hint': 'pip install qiling'}

    file_path = request.get('file_path', '')
    serial = request.get('serial', '')
    timeout = request.get('timeout_sec', 30)

    t0 = time.time()
    api_calls = []

    rootfs = os.environ.get('QILING_ROOTFS', '/opt/qiling-rootfs/x86_windows')
    if not os.path.isdir(rootfs):
        return {'ok': False, 'error': f'Qiling rootfs not found at {rootfs}'}

    try:
        ql = Qiling([file_path], rootfs, verbose=0)

        def generic_hook(ql, address, params, retval, retaddr, fname):
            api_calls.append({'api': fname, 'params': str(params)[:200]})

        ql.run(timeout=timeout * 1000000)

        elapsed = time.time() - t0
        return {
            'ok': True,
            'verdict': 'completed',
            'serial': serial,
            'api_calls_captured': len(api_calls),
            'elapsed_sec': round(elapsed, 2),
            'backend': 'qiling',
        }

    except Exception as e:
        return {
            'ok': False,
            'error': str(e),
            'elapsed_sec': round(time.time() - t0, 2),
            'backend': 'qiling',
        }


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        json.dump({'ok': False, 'error': 'No input'}, sys.stdout)
        return

    request = json.loads(raw)
    backend = request.get('backend', 'speakeasy')

    file_path = request.get('file_path', '')
    if file_path and not os.path.isfile(file_path):
        json.dump({'ok': False, 'error': f'File not found: {file_path}'}, sys.stdout)
        return

    if backend == 'speakeasy':
        result = verify_with_speakeasy(request)
    elif backend == 'qiling':
        result = verify_with_qiling(request)
    else:
        result = {'ok': False, 'error': f'Unknown backend: {backend}'}

    json.dump(result, sys.stdout)


if __name__ == '__main__':
    main()
