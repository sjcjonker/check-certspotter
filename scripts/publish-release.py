#!/usr/bin/env python3
"""Publish the tested workflow commit using its scoped GitHub Actions token."""
import ast
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request


def release_payload(repository, commit):
    tree = ast.parse(Path('check_certspotter.py').read_text())
    version = next(ast.literal_eval(node.value) for node in tree.body
                   if isinstance(node, ast.Assign) and any(
                       isinstance(target, ast.Name) and target.id == 'VERSION' for target in node.targets))
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid release version')
    notes = Path('RELEASE-NOTES.md').read_text()
    if notes.splitlines()[0] != '# ' + version:
        raise ValueError('Release notes do not match plugin version')
    return dict(tag_name='v' + version, target_commitish=commit,
                name=version, body=notes, draft=False, prerelease=False)


def main():
    if os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise RuntimeError('Releases are only published from tested main commits')
    repository = os.environ['GITHUB_REPOSITORY']
    payload = release_payload(repository, os.environ['GITHUB_SHA'])
    endpoint = f'https://api.github.com/repos/{repository}/releases'
    headers = {'Accept': 'application/vnd.github+json',
               'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
               'X-GitHub-Api-Version': '2022-11-28',
               'Content-Type': 'application/json'}
    try:
        with urllib.request.urlopen(urllib.request.Request(
                endpoint + '/tags/' + payload['tag_name'], headers=headers), timeout=30) as response:
            existing = json.load(response)
        if existing.get('draft'):
            raise RuntimeError('An existing draft requires manual review')
        print('Release already exists:', existing['html_url'])
        return
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    with urllib.request.urlopen(urllib.request.Request(
            endpoint, data=json.dumps(payload).encode(), headers=headers, method='POST'), timeout=30) as response:
        created = json.load(response)
    print('Published:', created['html_url'])


if __name__ == '__main__':
    main()
