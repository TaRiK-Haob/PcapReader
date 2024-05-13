import os
import sys
import dpkt
import datetime
import socket
from tqdm import tqdm

workspace=sys.path[0]

class flow:
    count = 1
    def __init__(self, flow_id) -> None:
        self.pkts = []
        self.flow_id = flow_id

    #TODO：加入新packet，更新流中的特征数据
    def add(self, data) -> None:
        self.pkts.append(data)
        self.count += 1
    
    def __str__(self) -> str:
        return str(self.count)

class packet:
    def __init__(self, timestamp, data) -> None:
        self.timestamp = timestamp
        self.data = data
    def __str__(self) -> str:
        return self.data

#获取流id
def get_flow_id(ip) -> str:
    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    protocol = ip.p
    # if p == 17 or p == 6:
    # 	src_port = ip.data.sport
    # 	dst_port = ip.data.dport

    if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
        src_port = ip.data.sport
        dst_port = ip.data.dport
    else:
        print("Not TCP/UDP skipped")
        return ""
    return "{}-{}-{}-{}-{}".format(src_ip, dst_ip, src_port, dst_port, protocol)

# 按照五元组进行分流
def quintuple_split(pcap:dpkt.pcap.Reader) -> list:
    flows = {}
    for timestamp, buf in tqdm(pcap):
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception as e:
            print(e)
            continue
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        ip = eth.data
        flow_id = get_flow_id(ip)

        # print(flow_id)
        pkt = packet(timestamp, ip.data)

        if flow_id in flows:
            flows[flow_id].add(pkt)
        else:
            flows[flow_id] = flow(flow_id)
            flows[flow_id].add(pkt)
    return list(flows.values())

#根据五元组分流后的数据提取特征
def quintuple_hanlde(data:list) -> None:
    for i in tqdm(data):
        i.flow_id
    return 

def get_flows(input_file) -> list:
    data = []
    flows = []
    with open(input_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        data = quintuple_split(pcap)
    quintuple_hanlde(data)
    return flows

            

def main(input, output):
    pcap_filelist = []
    for root, dirs, files in os.walk(input):
        for file in files:
            pcap_filelist.append(os.path.join(root, file))
    print("共计{}个pcap文件".format(len(pcap_filelist)))


    all_flows = []
    file_flows =[]
    for file in pcap_filelist:
        try:
            file_flows = get_flows(file)
        except Exception as e:
            print(e)
            pass
        if file_flows == False:
            print(file, "ERROR")
            continue
        if len(file_flows) <= 0:
            continue
        all_flows += file_flows
    
if __name__ == "__main__":
    #参数：pcap目录路径 csv输出文件
    _, input_dir, output_file = sys.argv
    main(input_dir, output_file)
