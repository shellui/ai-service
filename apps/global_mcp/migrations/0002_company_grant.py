import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('global_mcp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='GlobalAgentCompanyGrant',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('global_company_id', models.UUIDField(db_index=True)),
                ('regional_company_id', models.CharField(blank=True, default='', max_length=64)),
                ('region_code', models.CharField(blank=True, default='', max_length=32)),
                ('services', models.JSONField(default=list)),
                ('max_access_mode', models.CharField(default='ask', max_length=20)),
                ('max_read_level', models.CharField(default='safe', max_length=20)),
                ('max_destructive', models.BooleanField(default=False)),
                ('binding_version', models.PositiveIntegerField(default=1)),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'agent',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='company_grants',
                        to='global_mcp.globalagent',
                    ),
                ),
            ],
        ),
        migrations.AddConstraint(
            model_name='globalagentcompanygrant',
            constraint=models.UniqueConstraint(
                fields=('agent', 'global_company_id'),
                name='global_grant_agent_company_uniq',
            ),
        ),
    ]
