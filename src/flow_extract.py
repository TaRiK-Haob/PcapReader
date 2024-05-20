import os
import sys
import dpkt
import datetime
import socket
from tqdm import tqdm

workspace=sys.path[0]



class flow:
    def __init__(self, flow_id, timestamp, ip) -> None:
        self.flow_id = flow_id
        self.pkts = []                                  # 包长度序列
        self.pkts.append(ip.len)
        self.count = 1                                  # packet总数计数器
        self.start_time = timestamp
        self.end_time = timestamp                       # 流起始时间和结束时间
        self.timestamp = []                             # 每个packet 时间戳
        self.timestamp.append(timestamp)
        self.pkt_len_max = ip.len                       # 包长度最大值
        self.pkt_len_min  = ip.len                      # 包长度最小值
        self.pkt_len_sum = ip.len                       # 包长度总和
        self.pkt_len_avg = ip.len                       # 包长度平均值
        self.pkt_len_std = ip.len                       # 包长度标准差
        self.IPD_max = 0                                # 包间间隔最大
        self.IPD_min = 0                                # 包间间隔最小
        self.IPD_avg = 0                                # 包间间隔平均
        self.IPD_std = 0                                # 包间间隔标准差
        self.IPD = []                                   # 包间间隔序列

    # TODO：加入新packet，更新流中的特征数据
    def add(self, timestamp, ip) -> None:
        self.pkt_len_max = ip.len if ip.len >= self.pkt_len_max else self.pkt_len_max
        self.pkt_len_min = ip.len if ip.len <= self.pkt_len_min else self.pkt_len_min
        self.pkt_len_sum += ip.len

        self.pkts.append(ip.len)
        self.end_time = timestamp
        self.count += 1
    
    #TODO: 加入输出功能
    def __str__(self) -> str:
        return "{},{},{},{},{},{}".format(self.flow_id, 
                                       round((self.end_time - self.start_time),2), 
                                       self.count , 
                                       round((self.pkt_len_sum/self.count), 2),
                                       self.pkt_len_max, 
                                       self.pkt_len_min)
    


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

        if flow_id in flows:
            flows[flow_id].add(timestamp, ip)
        else:
            flows[flow_id] = flow(flow_id, timestamp, ip)
    return list(flows.values())

#*根据五元组分流后的数据提取特征
# def quintuple_handle(data:list) -> None:
#     for i in tqdm(data):
#         i.flow_id
#     return 

def get_flows(input_file) -> list:
    data = []
    flows = []
    with open(input_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        data = quintuple_split(pcap)
    #* quintuple_handle(data)
    return data

            

def main(input, output, label):
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

    with open(output, "w+", encoding="utf-8") as f:
        for flow in file_flows:
            print(flow,file = f)




if __name__ == "__main__":
    #参数：pcap目录路径 csv输出文件
    _ = sys.argv[0]
    input_dir = sys.argv[1]
    output_file = sys.argv[2]
    label = ""
    if len(sys.argv) >= 4:
        label = sys.argv[3]
    main(input_dir, output_file, label)
