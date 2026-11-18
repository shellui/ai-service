#!/usr/bin/env python3
"""Print public OpenAPI JSON for the current service (stdout)."""

import json
import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

import django

django.setup()
from drf_spectacular.generators import SchemaGenerator

schema = SchemaGenerator().get_schema(request=None, public=True)
json.dump(schema, sys.stdout)
