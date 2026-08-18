from django.core.management.base import BaseCommand
from scapy.all import sniff, IP
from django.utils import timezone
from dashboard.models import NetworkEvent
from dashboard.ml.feature_extractor import parse_pcap_to_features
from dashboard.ml.predictor import load_trained_models, predict_attack_types

import os
import tempfile
import threading

class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument(
            '--interface',
            type=str,
            default='Ethernet'
        )
        parser.add_argument(
            '--count',
            type=int,
            default=0,
            help='Number of packets to capture'
        )
    def handle(self, *args, **options):
        interface = options['interface']
        count = options['count']
        stop_file = 'stop_capture.flag'

        if os.path.exists(stop_file):
            os.remove(stop_file)
        self.stdout.write(
            self.style.SUCCESS(
                f"Live capture started on {interface}..."
            )
        )
        #lodingn the models 
        try:
            _, _, _, feature_names = load_trained_models()

            if not feature_names:
                self.stdout.write(
                    self.style.ERROR(
                        "Feature names could not be loaded."
                    )
                )
                return

            self.stdout.write(
                self.style.SUCCESS(
                    f"Loaded {len(feature_names)} ML features."
                )
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(
                    f"Could not load ML models: {e}"
                )
            )
            return
       #temp PCAP file
        temp_pcap = tempfile.NamedTemporaryFile(
            delete=False,
            suffix='.pcap'
        )
        temp_pcap.close()
        self.stdout.write(
            f"Temporary PCAP: {temp_pcap.name}"
        )
        packet_buffer = []
        #ml processing for predicaitons
        def process_ml():
            nonlocal packet_buffer
            if not packet_buffer:
                return
            try:

                self.stdout.write(
                    f"Processing {len(packet_buffer)} captured packets..."
                )
                # Write packets to temporary PCAP
                from scapy.utils import wrpcap
                wrpcap(
                    temp_pcap.name,
                    packet_buffer
                )
                # Convert packets to the same 78 features
                features_df = parse_pcap_to_features(
                    temp_pcap.name,
                    feature_names=feature_names
                )
                if features_df.empty:
                    self.stdout.write(
                        "No network flows generated yet."
                    )
                    return
                #predicaitons on XGboot and Isolation forest
                predictions = predict_attack_types(
                    features_df
                )
                #saving results to database
                for _, row in predictions.iterrows():
                    src_ip = row.get(
                        'src_ip',
                        '0.0.0.0'
                    )
                    dst_ip = row.get(
                        'dst_ip',
                        '0.0.0.0'
                    )
                    protocol = row.get(
                        'protocol',
                        'OTHER'
                    )
                    length = row.get(
                        'length',
                        0
                    )
                    is_anomaly = bool(
                        row.get(
                            'is_anomaly',
                            False
                        )
                    )
                    attack_type = row.get(
                        'attack_type',
                        ''
                    )

                    if not is_anomaly:
                        attack_type = ''
                    NetworkEvent.objects.create(
                        timestamp=timezone.now(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=protocol,
                        length=length,
                        is_anomaly=is_anomaly,
                        attack_type=attack_type
                    )
                    # Showing result in terminal
                    status = (
                        f"ANOMALY - {attack_type}"
                        if is_anomaly
                        else "NORMAL"
                    )
                    self.stdout.write(
                        f"{src_ip} -> {dst_ip} | "
                        f"{protocol} | {status}"
                    )
                # Clear processed packets
                packet_buffer = []
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f"ML processing error: {e}"
                    )
                )
        #packet callback
        def packet_callback(pkt):
            try:
                if IP not in pkt:
                    return
                packet_buffer.append(pkt)
                ip = pkt[IP]
                self.stdout.write(
                    f"Captured: "
                    f"{ip.src} -> {ip.dst}"
                )
                # Process every 10 packets
                if len(packet_buffer) >= 10:
                    process_ml()
            except Exception as e:
                self.stdout.write(
                    f"Packet error: {e}"
                )

        # statring the caputre
        try:

            sniff(
                iface=interface,
                prn=packet_callback,
                store=False,
                count=count,
                stop_filter=lambda pkt:
                    os.path.exists(stop_file)
            )
        except KeyboardInterrupt:
            self.stdout.write(
                "Capture interrupted."
            )
        finally:
            # Process remaining packets
            if packet_buffer:
                process_ml()
            # Remove temporary PCAP
            if os.path.exists(temp_pcap.name):
                try:
                    os.remove(temp_pcap.name)
                except Exception:
                    pass
            self.stdout.write(
                self.style.SUCCESS(
                    "Live capture stopped."
                )
            )