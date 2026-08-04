# most crucial file that converts pcap files or csv files into numberical features that model can understand for evaluations
import os
import numpy as np
import pandas as pd
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')  #models directory

#funciton created for features
def parse_pcap_to_features(pcap_path, feature_names=None):
#Extract network flow features from a PCAP file using Scapy.
#Returns a pandas DataFrame with the same columns as your feature_names.
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # reading all packets by scapy
    packets = rdpcap(pcap_path)
    print(f"Reading PCAP (using Scapy): {len(packets)} packets found")

    # this is how flow of storage is
    flows = defaultdict(lambda: {  #creats a place to group brackets
        'packets': [],
        'times': [],
        'src': None,
        'dst': None,
        'proto': None,
        'sport': 0,
        'dport': 0,
        'fwd_packets': 0,
        'bwd_packets': 0,
        'fwd_bytes': 0,
        'bwd_bytes': 0,
        'fwd_len_list': [],
        'bwd_len_list': [],
        'fwd_times': [],
        'bwd_times': [],
        'start_time': None,
        'end_time': None,
        'min_len': 999999,
        'max_len': 0,
        'len_list': [],
        'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0, 'ack': 0, 'urg': 0,
        'fwd_psh': 0, 'bwd_psh': 0,
        'fwd_urg': 0, 'bwd_urg': 0,
        'init_win_fwd': 0,
        'init_win_bwd': 0,
        'subflow_fwd_packets': 0,
        'subflow_bwd_packets': 0,
        'subflow_fwd_bytes': 0,
        'subflow_bwd_bytes': 0,
        'act_data_pkt_fwd': 0,
    })

    # itering over the packets
    for pkt in packets:
        if IP not in pkt:
            continue

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        # Identifying the transfer protocols
        if TCP in pkt:
            proto = 'TCP'
            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            flags = tcp.flags
            win = tcp.window
        elif UDP in pkt:
            proto = 'UDP'
            udp = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            flags = 0
            win = 0
        elif ICMP in pkt:
            proto = 'ICMP'
            sport = 0
            dport = 0
            flags = 0
            win = 0
        else:
            continue  

        flow_key = (src, dst, sport, dport, proto)   #creating the flow key
        flow = flows[flow_key]                   #stores every connnection

        if flow['start_time'] is None:
            flow['start_time'] = pkt.time
            flow['src'] = src
            flow['dst'] = dst
            flow['proto'] = proto
            flow['sport'] = sport
            flow['dport'] = dport
        flow['end_time'] = pkt.time
        flow['packets'].append(1)
        flow['times'].append(pkt.time)

        pkt_len = len(pkt)                  
        flow['len_list'].append(pkt_len)
        if pkt_len < flow['min_len']:
            flow['min_len'] = pkt_len
        if pkt_len > flow['max_len']:
            flow['max_len'] = pkt_len

        if src == flow['src']:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += pkt_len
            flow['fwd_len_list'].append(pkt_len)
            flow['fwd_times'].append(pkt.time)
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += pkt_len
            flow['bwd_len_list'].append(pkt_len)
            flow['bwd_times'].append(pkt.time)

        # the tcp flags
        #extracting TCP flag statisctis from packets and storing them in dictionary
        if proto == 'TCP':
            # Scapy uses bitmask for flags
            if flags & 0x01: flow['fin'] += 1
            if flags & 0x02: flow['syn'] += 1
            if flags & 0x04: flow['rst'] += 1
            if flags & 0x08: flow['psh'] += 1
            if flags & 0x10: flow['ack'] += 1
            if flags & 0x20: flow['urg'] += 1

            if src == flow['src']:
                if flags & 0x08: flow['fwd_psh'] += 1
                if flags & 0x20: flow['fwd_urg'] += 1
            else:
                if flags & 0x08: flow['bwd_psh'] += 1
                if flags & 0x20: flow['bwd_urg'] += 1

            if flow['init_win_fwd'] == 0 and src == flow['src']:
                flow['init_win_fwd'] = win
            if flow['init_win_bwd'] == 0 and dst == flow['dst']:
                flow['init_win_bwd'] = win

        if src == flow['src']:
            flow['subflow_fwd_packets'] += 1
            flow['subflow_fwd_bytes'] += pkt_len
        else:
            flow['subflow_bwd_packets'] += 1
            flow['subflow_bwd_bytes'] += pkt_len

        if src == flow['src']:
            flow['act_data_pkt_fwd'] = 1

    print(f"Total packets processed: {len(packets)}")
    print(f"Flows found: {len(flows)}")

    # calculating the features flow
    rows = []
    for flow in flows.items():
        total_packets = len(flow['packets'])
        if total_packets == 0:
            continue

        fwd_packets = flow['fwd_packets']
        bwd_packets = flow['bwd_packets']
        fwd_bytes = flow['fwd_bytes']
        bwd_bytes = flow['bwd_bytes']
        total_bytes = fwd_bytes + bwd_bytes

        duration = flow['end_time'] - flow['start_time'] if flow['end_time'] else 0
        if duration < 0.001:
            duration = 0.001

        len_list = flow['len_list']
        min_len = flow['min_len'] if flow['min_len'] != 999999 else 0
        max_len = flow['max_len'] if flow['max_len'] != 0 else 0

        mean_len = np.mean(len_list) if len_list else 0
        std_len = np.std(len_list) if len_list else 0
        var_len = np.var(len_list) if len_list else 0

        # IATs
        times = sorted(flow['times'])
        iats = [float(times[i] - times[i-1]) for i in range(1, len(times))]
        iat_mean = np.mean(iats) if iats else 0.0
        iat_max = max(iats) if iats else 0.0
        iat_min = min(iats) if iats else 0.0
        iat_total = sum(iats) if iats else 0.0

        fwd_times = sorted(flow['fwd_times'])
        fwd_iats = [float(fwd_times[i] - fwd_times[i-1]) for i in range(1, len(fwd_times))]
        fwd_iat_total = sum(fwd_iats) if fwd_iats else 0.0
        fwd_iat_mean = np.mean(fwd_iats) if fwd_iats else 0.0
        fwd_iat_max = max(fwd_iats) if fwd_iats else 0.0
        fwd_iat_min = min(fwd_iats) if fwd_iats else 0.0

        bwd_times = sorted(flow['bwd_times'])
        bwd_iats = [float(bwd_times[i] - bwd_times[i-1]) for i in range(1, len(bwd_times))]
        bwd_iat_total = sum(bwd_iats) if bwd_iats else 0.0
        bwd_iat_mean = np.mean(bwd_iats) if bwd_iats else 0.0
        bwd_iat_max = max(bwd_iats) if bwd_iats else 0.0
        bwd_iat_min = min(bwd_iats) if bwd_iats else 0.0

        # here the feature dicitionary is built
        features = {
            'Flow Duration': duration,
            'Total Fwd Packets': fwd_packets,
            'Total Backward Packets': bwd_packets,
            'Total Length of Fwd Packets': fwd_bytes,
            'Total Length of Bwd Packets': bwd_bytes,
            'Fwd Packet Length Max': max(flow['fwd_len_list']) if flow['fwd_len_list'] else 0,
            'Fwd Packet Length Min': min(flow['fwd_len_list']) if flow['fwd_len_list'] else 0,
            'Fwd Packet Length Mean': np.mean(flow['fwd_len_list']) if flow['fwd_len_list'] else 0,
            'Bwd Packet Length Max': max(flow['bwd_len_list']) if flow['bwd_len_list'] else 0,
            'Bwd Packet Length Min': min(flow['bwd_len_list']) if flow['bwd_len_list'] else 0,
            'Bwd Packet Length Mean': np.mean(flow['bwd_len_list']) if flow['bwd_len_list'] else 0,
            'Flow Bytes/s': total_bytes / duration,
            'Flow Packets/s': total_packets / duration,
            'Flow IAT Mean': iat_mean,
            'Flow IAT Max': iat_max,
            'Flow IAT Min': iat_min,
            'Fwd IAT Total': fwd_iat_total,
            'Fwd IAT Mean': fwd_iat_mean,
            'Fwd IAT Max': fwd_iat_max,
            'Fwd IAT Min': fwd_iat_min,
            'Bwd IAT Total': bwd_iat_total,
            'Bwd IAT Mean': bwd_iat_mean,
            'Bwd IAT Max': bwd_iat_max,
            'Bwd IAT Min': bwd_iat_min,
            'Fwd PSH Flags': flow['fwd_psh'],
            'Bwd PSH Flags': flow['bwd_psh'],
            'Fwd URG Flags': flow['fwd_urg'],
            'Bwd URG Flags': flow['bwd_urg'],
            'Fwd Header Length': fwd_packets * 20,
            'Bwd Header Length': bwd_packets * 20,
            'Fwd Packets/s': fwd_packets / duration,
            'Bwd Packets/s': bwd_packets / duration,
            'Min Packet Length': min_len,
            'Max Packet Length': max_len,
            'Packet Length Mean': mean_len,
            'Packet Length Std': std_len,
            'Packet Length Variance': var_len,
            'FIN Flag Count': flow['fin'],
            'SYN Flag Count': flow['syn'],
            'RST Flag Count': flow['rst'],
            'PSH Flag Count': flow['psh'],
            'ACK Flag Count': flow['ack'],
            'URG Flag Count': flow['urg'],
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': bwd_packets / fwd_packets if fwd_packets > 0 else 0,
            'Average Packet Size': total_bytes / total_packets if total_packets > 0 else 0,
            'Avg Fwd Segment Size': fwd_bytes / fwd_packets if fwd_packets > 0 else 0,
            'Avg Bwd Segment Size': bwd_bytes / bwd_packets if bwd_packets > 0 else 0,
            'Fwd Header Length.1': fwd_packets * 20,
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': flow['subflow_fwd_packets'],
            'Subflow Fwd Bytes': flow['subflow_fwd_bytes'],
            'Subflow Bwd Packets': flow['subflow_bwd_packets'],
            'Subflow Bwd Bytes': flow['subflow_bwd_bytes'],
            'Init_Win_bytes_forward': flow['init_win_fwd'],
            'Init_Win_bytes_backward': flow['init_win_bwd'],
            'act_data_pkt_fwd': flow['act_data_pkt_fwd'],
            'min_seg_size_forward': min(flow['fwd_len_list']) if flow['fwd_len_list'] else 0,
            'Active Mean': 0,
            'Active Max': 0,
            'Active Min': 0,
            'Active Std': 0,
            'Idle Mean': 0,
            'Idle Max': 0,
            'Idle Min': 0,
            'Idle Std': 0,
            'src_ip': flow['src'],
            'dst_ip': flow['dst'],
            'protocol': flow['proto'],
            'length': len(flow['len_list']) if flow['len_list'] else 0,
        }

        # Protocol features 
        features['protocol_TCP'] = 1 if flow['proto'] == 'TCP' else 0
        features['protocol_UDP'] = 1 if flow['proto'] == 'UDP' else 0
        features['protocol_ICMP'] = 1 if flow['proto'] == 'ICMP' else 0

        rows.append(features)

    df = pd.DataFrame(rows)

    if feature_names:
        for col in feature_names:
            if col not in df.columns:
                df[col] = 0.0
        df = df[feature_names]
    else:
        print("No feature_names provided; returning all computed features.")

    df = df.fillna(0).replace([np.inf, -np.inf], 0)
    print(f"Extracted features: {len(df)} flows, {len(df.columns)} features each")
    return df

# loading csv files
def extract_features_from_csv(csv_path, feature_names=None):
#Load features from a CSV file.
# If a 'Label' column exists, it is preserved for evaluation.
    df = pd.read_csv(csv_path)
    
    # stripping down any spaces
    df.columns = df.columns.str.strip()
    
    # Store Label column if it exists
    label_col = None
    if 'Label' in df.columns:
        label_col = df['Label'].copy()
    
    if feature_names:
        #making sure all feature columns exist
        for col in feature_names:
            if col not in df.columns:
                df[col] = 0.0
        # keeping here only feature columns
        df = df[feature_names]
        
        # adding label if not existed
        if label_col is not None:
            df['Label'] = label_col
    
    return df.fillna(0).replace([np.inf, -np.inf], 0) #replaces the positve and negative infinty with 0