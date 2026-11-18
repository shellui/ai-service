from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('connector', '0003_mcp_call_log_owner_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='mcpcalllog',
            name='plane',
            field=models.CharField(
                choices=[('region', 'Region'), ('global', 'Global')],
                default='region',
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name='mcpcalllog',
            name='owner_sub',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AlterField(
            model_name='mcpcalllog',
            name='company_id',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddIndex(
            model_name='mcpcalllog',
            index=models.Index(fields=['plane', 'owner_sub', 'created_at'], name='mcpcall_plane_owner_idx'),
        ),
    ]
