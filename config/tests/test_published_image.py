"""The published image is the production stage, not the dev stage."""

from __future__ import annotations

from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[2]


def _env_assignments(stage: str) -> list[str]:
    assignments: list[str] = []
    in_env = False
    for line in stage.splitlines():
        stripped = line.strip()
        if stripped.startswith('ENV '):
            in_env = True
            stripped = stripped[4:].strip()
        elif in_env and stripped and not line.startswith((' ', '\t')):
            in_env = False
        if not in_env:
            continue
        text = stripped.rstrip('\\').strip()
        if text:
            assignments.append(text)
        if not stripped.endswith('\\'):
            in_env = False
    return assignments


def _stages(dockerfile: str) -> list[tuple[str, str]]:
    chunks = []
    current_name = ''
    current: list[str] = []
    for line in dockerfile.splitlines():
        if line.startswith('FROM '):
            if current_name or current:
                chunks.append((current_name, '\n'.join(current)))
            parts = line.split()
            current_name = parts[parts.index('AS') + 1] if 'AS' in parts else ''
            current = [line]
            continue
        current.append(line)
    if current_name or current:
        chunks.append((current_name, '\n'.join(current)))
    return chunks


class PublishedImageTests(SimpleTestCase):
    def test_production_stage_is_last_and_keeps_debug_false(self):
        text = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        stages = _stages(text)
        names = [name for name, _body in stages]
        self.assertEqual(names[-1], 'production')
        self.assertLess(names.index('dev'), names.index('production'))
        dev = dict(stages)['dev']
        production = dict(stages)['production']
        self.assertIn('DEBUG=true', dev)
        self.assertIn('com.shellui.image-stage=dev', dev)
        self.assertIn('DEBUG=false', production)
        self.assertIn('com.shellui.image-stage=production', production)
        self.assertIn('production image must keep DEBUG=false', production)
        debug_env = [item for item in _env_assignments(production) if item.startswith('DEBUG=')]
        self.assertEqual(debug_env, ['DEBUG=false'])

    def test_release_builds_target_the_production_stage(self):
        publish = (ROOT / '.github/workflows/publish.yml').read_text(encoding='utf-8')
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        pre_release = (ROOT / 'tools/pre-release-check.sh').read_text(encoding='utf-8')
        self.assertIn('\n          target: production\n', publish)
        self.assertNotIn('target: dev', publish)
        self.assertIn('\n          target: production\n', ci)
        self.assertIn('docker build --target production', pre_release)
        self.assertIn('com.shellui.image-stage', pre_release)
        self.assertIn('DEBUG=false', pre_release)

    def test_dev_compose_images_are_not_the_published_repository(self):
        compose = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')
        e2e = (ROOT / 'tools/mcp-e2e/docker-compose.yml').read_text(encoding='utf-8')
        self.assertNotIn('image: shellui/ai-service', compose)
        self.assertNotIn('image: shellui/ai-service', e2e)
        self.assertIn('target: dev', compose)
        self.assertIn('image: ai-service:local', compose)
        self.assertIn('image: ai-service:mcp-e2e', e2e)
