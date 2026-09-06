import pandas as pd
from nfstream import NFStreamer

streamer = NFStreamer(
    source="local_attacks.pcap",
    statistical_analysis=True,
    idle_timeout=1,
    active_timeout=2
)
rows = []
for flow in streamer:
    total_pkts = flow.bidirectional_packets
    total_bytes = flow.bidirectional_bytes
    duration_sec = flow.bidirectional_duration_ms / 1000.0
    duration_micro = flow.bidirectional_duration_ms * 1000.0
    rows.append({
        'Total_Packets': total_pkts,
        'Total_Bytes': total_bytes,
        'Src2Dst_Ratio': (flow.src2dst_bytes / total_bytes) if total_bytes > 0 else 0.0,
        'Flow Duration': duration_micro,
        'Flow Bytes/s': (total_bytes / duration_sec) if duration_sec > 0 else 0.0,
        'Flow Packets/s': (total_pkts / duration_sec) if duration_sec > 0 else 0.0,
        'Packet Length Mean': flow.bidirectional_mean_ps,
        'Packet Length Std': flow.bidirectional_stddev_ps,
        'FIN Flag Count': getattr(flow, 'src2dst_fin_packets', 0) + getattr(flow, 'dst2src_fin_packets', 0),
        'SYN Flag Count': getattr(flow, 'src2dst_syn_packets', 0) + getattr(flow, 'dst2src_syn_packets', 0),
        'RST Flag Count': getattr(flow, 'src2dst_rst_packets', 0) + getattr(flow, 'dst2src_rst_packets', 0),
        'PSH Flag Count': getattr(flow, 'src2dst_psh_packets', 0) + getattr(flow, 'dst2src_psh_packets', 0),
        'ACK Flag Count': getattr(flow, 'src2dst_ack_packets', 0) + getattr(flow, 'dst2src_ack_packets', 0),
        'URG Flag Count': getattr(flow, 'src2dst_urg_packets', 0) + getattr(flow, 'dst2src_urg_packets', 0),
        'Min Packet Length': flow.bidirectional_min_ps,
        'Label': 'DDoS'
    })
df_synthetic = pd.DataFrame(rows)
df_synthetic.to_csv("synthetic_attacks.csv", index=False)
print(f"[+] Extracted {len(df_synthetic)} attack flows to synthetic_attacks.csv")
