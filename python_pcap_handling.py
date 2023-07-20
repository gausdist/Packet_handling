# Some starter functions for handling TCP/IP packets in Python

import pandas as pd
import numpy as np
import datetime
import socket
import dpkt

# Assumes timestamp is nanos granularity


def eth_pcap_to_df(pcap_path: str, encoding: str, payload_text_structure:str) -> pd.DataFrame:
    data = []
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            payload = ip.data.data.decode(encoding)
            data.append([timestamp, socket.inet_ntop(socket.AF_INET, ip.src), payload])
    df = pd.DataFrame(data, columns=['timestamp', 'src_ip', 'payload'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    df['timestamp'] = df['timestamp'].diff()
    df.at[0, 'timestamp'] = datetime.timedelta(0)
    df['timestamp'] = df['timestamp'].cumsum()
    extract = df['payload'].str.extract(payload_text_structure)
    df = pd.concat([df, extract], axis=1)
    df = df.drop(columns=['payload'])
    return df