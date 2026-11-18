"""Generate an RSA key pair for ai-service downstream-token delegation."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.authapi.ai_service_jwks import compute_rsa_kid, generate_rsa_key_pair


class Command(BaseCommand):
    help = 'Generate RSA keys for AI_SERVICE_SIGNING_KEY (RS256 delegation to identity).'
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument('--bits', type=int, default=3072, help='RSA key size (min 2048, default 3072).')
        parser.add_argument(
            '--shell',
            action='store_true',
            help='Print export lines for eval, e.g. eval "$(uv run python manage.py generate_signing_key --shell)".',
        )

    def handle(self, *args, **options):
        private_pem, public_pem = generate_rsa_key_pair(key_size=options['bits'])
        kid = compute_rsa_kid(public_pem)
        private_escaped = private_pem.replace('\n', '\\n')

        if options['shell']:
            self.stdout.write(f'export AI_SERVICE_SIGNING_KID={kid}')
            self.stdout.write(f'export AI_SERVICE_SIGNING_KEY="{private_escaped}"')
            return

        self.stdout.write('Generated RSA key pair for ai-service delegation.\n')
        self.stdout.write('Add to your environment (.env or secret manager):\n\n')
        self.stdout.write(f'AI_SERVICE_SIGNING_KID={kid}')
        self.stdout.write(f'AI_SERVICE_SIGNING_KEY="{private_escaped}"')
        self.stdout.write('\nSet AI_SERVICE_ISSUER to this service public origin (for example https://ai.shellui.com).\n')
        self.stdout.write('Identity verifies requests via GET {AI_SERVICE_ISSUER}/.well-known/jwks.json\n')
        self.stdout.write(
            self.style.WARNING('Keep AI_SERVICE_SIGNING_KEY secret. Never commit it to git.')
        )
