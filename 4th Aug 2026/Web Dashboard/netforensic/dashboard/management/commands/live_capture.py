#definining live captures
from django.core.management.base import BaseCommand
from scapy.all import sniff, IP, TCP, UDP, ICMP
from dashboard.models import NetworkEvent
from django.utils import timezone
import os

class Command(BaseCommand): #creates new Django mangement command by inherting form BaseCommand which enables to 
    def add_arguments(self, parser):   #this is used to read in terminal
        parser.add_argument('--interface', type=str, default='Ethernet')  #here i have used interface for ethernet
        parser.add_argument('--count', type=int, default=0, help='Number of packets to capture')

    def handle(self, *args, **options):  #main function defined  for calling it
        interface = options['interface']
        stop_file = 'stop_capture.flag'

        # checks the old file and removes its
        if os.path.exists(stop_file):
            os.remove(stop_file)

        self.stdout.write(f"Live capture started on {interface}...")
        self.stdout.write("Packets will appear below:")

        def packet_callback(pkt):
            try:
                if IP in pkt:
                    ip = pkt[IP]
                    src = ip.src
                    dst = ip.dst
                    
                    if TCP in pkt:
                        proto = 'TCP'
                    elif UDP in pkt:
                        proto = 'UDP'
                    elif ICMP in pkt:
                        proto = 'ICMP'
                    else:
                        proto = 'OTHER'

                    NetworkEvent.objects.create(
                        timestamp=timezone.now(),
                        src_ip=src,
                        dst_ip=dst,
                        protocol=proto,
                        length=len(pkt),
                        is_anomaly=False,
                    )
                    self.stdout.write(f"Source: {src} -> Destination: {dst} | {proto}") #showing source to destinatin 
            except:
                pass

        try:
            # stoping the captures
            sniff(
                iface=interface,
                prn=packet_callback,
                store=False,
                stop_filter=lambda pkt: os.path.exists(stop_file)
            )
        except KeyboardInterrupt:
            pass
        self.stdout.write("Live capture stopped.")