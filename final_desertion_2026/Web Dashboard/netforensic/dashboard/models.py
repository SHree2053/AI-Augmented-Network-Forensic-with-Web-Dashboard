from django.db import models
from django.utils import timezone

#here class alert give the level of the attack types such as high, medium,low and info
class Alert(models.Model):
    LEVEL_CHOICES = [
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Info', 'Info'),
    ]
    
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES, default='Info')
    message = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now) #this enable sto pass an explict timesatmp while defaulting sensibilby when don't
    is_resolved = models.BooleanField(default=False)
    
    def __str__(self):
        return f"[{self.level}] {self.message[:50]}"
#here class netowkr event shows type of protcols such as TCP, UDP etct
class NetworkEvent(models.Model):
    PROTOCOL_CHOICES = [
        ('TCP', 'TCP'),
        ('UDP', 'UDP'),
        ('ICMP', 'ICMP'),
        ('OTHER', 'OTHER'),
    ]
    
    timestamp = models.DateTimeField(default=timezone.now)
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=10, choices=PROTOCOL_CHOICES, default='OTHER')
    length = models.IntegerField()
    is_anomaly = models.BooleanField(default=False)
    attack_type = models.CharField(max_length=50, blank=True, null=True)
    
    def __str__(self):
        return f"{self.timestamp} | {self.src_ip} -> {self.dst_ip} | {self.protocol}"