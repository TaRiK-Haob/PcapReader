import os
import sys
import dpkt
import datetime
import socket

workspace=sys.path[0]


def get_flows(input_file):
	with open(input_file, 'rb') as f:
		pcap = dpkt.pcap.Reader(f)
		cnt = 10
		for timestamp, buf in pcap:
			print('Timestamp: ', str(datetime.timedelta(timestamp)))

def main(input, output):
	pcap_filelist = []
	for root, dirs, files in os.walk(input):
		for file in files:
			pcap_filelist.append(os.path.join(root, file))
	print("共计{}个pcap文件".format(len(pcap_filelist)))


	all_flows = []
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
