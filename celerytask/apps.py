from __future__ import unicode_literals

from django.apps import AppConfig


class CeleryTaskConfig(AppConfig):
    name = 'celerytask'

    def ready(self):
        import celerytask.signals
