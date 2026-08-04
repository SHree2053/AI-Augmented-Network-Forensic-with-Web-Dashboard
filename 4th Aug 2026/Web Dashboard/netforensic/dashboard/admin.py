from django.contrib import admin
from .models import Alert, NetworkEvent

#creates the alret model in the admin model
@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'level', 'message', 'is_resolved')
    list_filter = ('level', 'is_resolved')
    search_fields = ('message',)
    ordering = ('-timestamp',)


#regiser the networkevent on djnaog admin
@admin.register(NetworkEvent)
class NetworkEventAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'src_ip', 'dst_ip', 'protocol', 'length', 'is_anomaly')
    list_filter = ('protocol', 'is_anomaly')
    search_fields = ('src_ip', 'dst_ip')
    ordering = ('-timestamp',)