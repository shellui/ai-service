from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='McpCallLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('company_id', models.PositiveIntegerField()),
                ('agent_id', models.CharField(blank=True, default='', max_length=128)),
                ('agent_name', models.CharField(blank=True, default='', max_length=200)),
                ('client_id', models.CharField(blank=True, default='', max_length=128)),
                ('client_name', models.CharField(blank=True, default='', max_length=120)),
                ('token_kind', models.CharField(blank=True, default='', max_length=32)),
                ('user_id', models.PositiveIntegerField(blank=True, null=True)),
                ('user_email', models.CharField(blank=True, default='', max_length=254)),
                ('service', models.CharField(blank=True, default='', max_length=32)),
                ('tool_name', models.CharField(blank=True, default='', max_length=255)),
                ('wrapper_tool', models.CharField(blank=True, default='', max_length=64)),
                ('arguments_redacted', models.JSONField(blank=True, default=dict)),
                ('status', models.CharField(
                    choices=[
                        ('allowed', 'Allowed'),
                        ('denied', 'Denied'),
                        ('waiting_approval', 'Waiting approval'),
                        ('failed', 'Failed'),
                        ('error', 'Error'),
                    ],
                    max_length=32,
                )),
                ('status_code', models.PositiveIntegerField(default=0)),
                ('error_code', models.CharField(blank=True, default='', max_length=64)),
                ('error_message', models.CharField(blank=True, default='', max_length=500)),
                ('duration_ms', models.PositiveIntegerField(default=0)),
                ('approval_id', models.CharField(blank=True, default='', max_length=64)),
                ('approval_channel', models.CharField(
                    choices=[('form', 'Form'), ('link', 'Link'), ('none', 'None')],
                    default='none',
                    max_length=8,
                )),
                ('approval_outcome', models.CharField(blank=True, default='', max_length=32)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['company_id', 'created_at'], name='mcpcall_co_created_idx'),
                    models.Index(fields=['company_id', 'agent_id'], name='mcpcall_co_agent_idx'),
                ],
            },
        ),
    ]
