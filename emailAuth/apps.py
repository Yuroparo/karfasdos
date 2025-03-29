from django.apps import AppConfig





class EmailauthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'

    name = 'emailAuth'

    def ready(self):
        import emailAuth.signals  # this will register your signals
        # noqa
