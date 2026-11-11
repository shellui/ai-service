from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('connector', '0001_mcp_call_log'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpcalllog',
            name='access_kind',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='global_agent_id',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='global_company_id',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='operation_title',
            field=models.CharField(blank=True, default='', max_length=200),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='outcome',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='resource_label',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
    ]
