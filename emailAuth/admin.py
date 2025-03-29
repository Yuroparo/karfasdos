from django.contrib import admin
from .models import User, Voice, TTSConversion, UserHistory, Payment

admin.site.register(User)
admin.site.register(Voice)
admin.site.register(TTSConversion)
admin.site.register(UserHistory)
admin.site.register(Payment)