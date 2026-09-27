"""Importing server helpers must not interrupt a live server's queued jobs."""

import json
import os
import subprocess
import sys


def test_import_does_not_recover_jobs_until_launcher_calls_it(tmp_path):
    job = tmp_path / 'jobs' / 'example'
    job.mkdir(parents=True)
    status = job / 'status.json'
    status.write_text(json.dumps({'state': 'running', 'message': 'in progress'}),
                      encoding='utf-8')
    env = {**os.environ, 'S2R_REVIEW_DATA': str(tmp_path)}
    imported = subprocess.run([sys.executable, '-B', '-c', 'import review.main'],
                              env=env, capture_output=True, text=True, timeout=15)
    assert imported.returncode == 0, imported.stderr
    assert json.loads(status.read_text(encoding='utf-8'))['state'] == 'running'

    recovered = subprocess.run(
        [sys.executable, '-B', '-c',
         'from review.main import recover_interrupted_jobs; recover_interrupted_jobs()'],
        env=env, capture_output=True, text=True, timeout=15)
    assert recovered.returncode == 0, recovered.stderr
    assert json.loads(status.read_text(encoding='utf-8'))['state'] == 'interrupted'
