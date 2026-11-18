from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('connector', '0004_mcp_call_log_plane'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpcalllog',
            name='correlation_id',
            field=models.UUIDField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='regional_company_id',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='region',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
    ]
