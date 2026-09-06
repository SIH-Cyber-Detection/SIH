import math
import time
import os
import joblib
import numpy as np
import pandas as pd
from collections import Counter, defaultdict
from datetime import datetime, timezone
from nfstream import NFStreamer

MODEL_PATH = "engine_a_rf.joblib"
rf_engine_a = joblib.load(MODEL_PATH)

FEATURE_COLUMNS = [
    'Total_Packets', 'Total_Bytes', 'Src2Dst_Ratio',
    'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
    'Packet Length Mean', 'Packet Length Std',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'Min Packet Length'
]

def format_timestamps(flow_ms=None):
    if flow_ms is not None:
        dt = datetime.fromtimestamp(flow_ms / 1000.0, tz=timezone.utc)
        epoch_ms = int(flow_ms)
    else:
        dt = datetime.now(timezone.utc)
        epoch_ms = int(dt.timestamp() * 1000)
    iso_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"
    return iso_str, epoch_ms

def shannon_entropy_checker(domain):
    if not isinstance(domain, str):
        return 0
    labels = domain.strip('.').split('.')
    core_label = max(labels, key=len) if labels else ""
    if len(core_label) == 0:
        return 0
    collexion = Counter(core_label)
    length = len(core_label)
    entropy = 0
    for i in collexion.values():
        p = i / length
        entropy += p * math.log2(p)
    return -entropy

def run_pipeline(source_target: str = "lo"):
    is_pcap = os.path.isfile(source_target)
    
    streamer = NFStreamer(
        source=source_target,
        statistical_analysis=True,
        splt_analysis=0,
        n_dissections=20,
        idle_timeout=15 if is_pcap else 1,
        active_timeout=30 if is_pcap else 1,
        bpf_filter="not port 8000" if not is_pcap else None
    )

    beacon_tracker = defaultdict(list)
    BEACON_WINDOW_SIZE = 6
    flows_count = 0
    bytes_count = 0
    alerts_count = 0
    start_wall_time = time.time()

    for flow in streamer:
        flows_count += 1
        bytes_count += flow.bidirectional_bytes
        flow_id = f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}"
        
        flow_ms = flow.bidirectional_first_seen_ms
        iso_ts, epoch_ms = format_timestamps(flow_ms)
        is_threat_detected = False

        total_packets = flow.bidirectional_packets
        total_bytes = flow.bidirectional_bytes
        duration_sec = flow.bidirectional_duration_ms / 1000.0
        duration_micro = flow.bidirectional_duration_ms * 1000.0

        src2dst_ratio = (flow.src2dst_bytes / total_bytes) if total_bytes > 0 else 0.0
        flow_bytes_s = (total_bytes / duration_sec) if duration_sec > 0 else 0.0
        flow_packets_s = (total_packets / duration_sec) if duration_sec > 0 else 0.0

        fin_flags = getattr(flow, 'src2dst_fin_packets', 0) + getattr(flow, 'dst2src_fin_packets', 0)
        syn_flags = getattr(flow, 'src2dst_syn_packets', 0) + getattr(flow, 'dst2src_syn_packets', 0)
        rst_flags = getattr(flow, 'src2dst_rst_packets', 0) + getattr(flow, 'dst2src_rst_packets', 0)
        psh_flags = getattr(flow, 'src2dst_psh_packets', 0) + getattr(flow, 'dst2src_psh_packets', 0)
        ack_flags = getattr(flow, 'src2dst_ack_packets', 0) + getattr(flow, 'dst2src_ack_packets', 0)
        urg_flags = getattr(flow, 'src2dst_urg_packets', 0) + getattr(flow, 'dst2src_urg_packets', 0)

        feature_vector = pd.DataFrame([[
            total_packets, total_bytes, src2dst_ratio,
            duration_micro, flow_bytes_s, flow_packets_s,
            flow.bidirectional_mean_ps, flow.bidirectional_stddev_ps,
            fin_flags, syn_flags, rst_flags,
            psh_flags, ack_flags, urg_flags,
            flow.bidirectional_min_ps
        ]], columns=FEATURE_COLUMNS)

        l4_prediction = rf_engine_a.predict(feature_vector)[0]

        if l4_prediction != "BENIGN":
            alerts_count += 1
            is_threat_detected = True
            yield ("ALERT", {
                "timestamp_iso": iso_ts,
                "timestamp_epoch_ms": epoch_ms,
                "engine": "ENGINE_A_VOLUMETRIC",
                "flow_id": flow_id,
                "threat_class": l4_prediction,
                "confidence_score": 0.95,
                "metrics": {
                    "total_packets": total_packets,
                    "flow_bytes_s": round(flow_bytes_s, 2),
                    "flow_packets_s": round(flow_packets_s, 2),
                    "syn_flags": syn_flags
                }
            })

        is_dns = (flow.protocol in (6, 17)) and (flow.dst_port == 53 or flow.src_port == 53)
        if is_dns and flow.requested_server_name:
            domain = flow.requested_server_name
            entropy = shannon_entropy_checker(domain)
            labels = domain.strip('.').split('.')
            core_label = max(labels, key=len) if labels else ""
            if entropy > 3.5 and len(core_label) > 10:
                alerts_count += 1
                is_threat_detected = True
                yield ("ALERT", {
                    "timestamp_iso": iso_ts,
                    "timestamp_epoch_ms": epoch_ms,
                    "engine": "ENGINE_B_DNS_HEURISTIC",
                    "flow_id": flow_id,
                    "threat_class": "DNS_DGA_OR_TUNNELING",
                    "confidence_score": round(min(0.99, 0.70 + ((entropy - 3.5) / 1.0) * 0.29), 2),
                    "evidence": {"domain": domain, "label": core_label, "entropy": round(entropy, 4), "length": len(core_label)}
                })

        # Normalize Layer 3 ICMP to port 0 to prevent tracker fracturing
        normalized_port = 0 if flow.protocol == 1 else flow.dst_port
        channel_key = (flow.src_ip, flow.dst_ip, normalized_port)
        
        timestamp_float = flow_ms / 1000.0
        beacon_tracker[channel_key].append(timestamp_float)
        if len(beacon_tracker[channel_key]) > BEACON_WINDOW_SIZE:
            beacon_tracker[channel_key].pop(0)

        if len(beacon_tracker[channel_key]) == BEACON_WINDOW_SIZE:
            history = beacon_tracker[channel_key]
            deltas = [history[i] - history[i - 1] for i in range(1, len(history))]
            mean_interval = np.mean(deltas)
            std_interval = np.std(deltas)
            if mean_interval > 0:
                cv = std_interval / mean_interval
                if cv <= 0.20 and mean_interval >= 5.0:
                    alerts_count += 1
                    is_threat_detected = True
                    yield ("ALERT", {
                        "timestamp_iso": iso_ts,
                        "timestamp_epoch_ms": epoch_ms,
                        "engine": "ENGINE_C_BEACONING",
                        "channel": f"{flow.src_ip} -> {flow.dst_ip}:{flow.dst_port}",
                        "threat_class": "BOTNET_C2_BEACONING",
                        "confidence_score": round(float(1.0 - cv), 2),
                        "evidence": {"observed_flows": BEACON_WINDOW_SIZE, "mean_interval_sec": round(float(mean_interval), 2), "cv": round(float(cv), 4)}
                    })
                    beacon_tracker[channel_key] = [timestamp_float]

        is_tls = flow.protocol == 6 and (flow.dst_port == 443 or flow.src_port == 443)
        if is_tls:
            if not flow.requested_server_name:
                alerts_count += 1
                is_threat_detected = True
                yield ("ALERT", {
                    "timestamp_iso": iso_ts,
                    "timestamp_epoch_ms": epoch_ms,
                    "engine": "ENGINE_D_ENCRYPTED_METADATA",
                    "flow_id": flow_id,
                    "threat_class": "SUSPICIOUS_DIRECT_TLS_C2",
                    "confidence_score": 0.85,
                    "evidence": {"description": "Encrypted session to direct IP without SNI"}
                })
            elif flow.bidirectional_packets < 10 and flow.bidirectional_bytes < 3000:
                alerts_count += 1
                is_threat_detected = True
                yield ("ALERT", {
                    "timestamp_iso": iso_ts,
                    "timestamp_epoch_ms": epoch_ms,
                    "engine": "ENGINE_D_ENCRYPTED_METADATA",
                    "flow_id": flow_id,
                    "threat_class": "ANOMALOUS_LIGHTWEIGHT_TLS_BURST",
                    "confidence_score": 0.65,
                    "evidence": {"sni": flow.requested_server_name}
                })

        if not is_threat_detected:
            yield ("ALERT", {
                "timestamp_iso": iso_ts,
                "timestamp_epoch_ms": epoch_ms,
                "engine": "PASSIVE_INSPECTION",
                "flow_id": flow_id,
                "threat_class": "BENIGN_TRAFFIC",
                "confidence_score": 0.99,
                "evidence": {"protocol": flow.protocol, "packets": flow.bidirectional_packets, "bytes": flow.bidirectional_bytes}
            })

        if flows_count % 10 == 0:
            elapsed = max(time.time() - start_wall_time, 0.001)
            t_iso, t_epoch = format_timestamps()
            yield ("TELEMETRY", {
                "timestamp_iso": t_iso,
                "timestamp_epoch_ms": t_epoch,
                "flows_processed": flows_count,
                "bytes_processed": bytes_count,
                "alerts_count": alerts_count,
                "elapsed_sec": round(elapsed, 2),
                "sustained_fps": round(flows_count / elapsed, 1),
                "sustained_mbps": round((bytes_count * 8) / (elapsed * 1_000_000), 2)
            })