import os
import sys
import dpkt
import datetime
import socket
from tqdm import tqdm
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd


df = pd.read_csv("../output/output.csv",delimiter=',')

data = df["flow_id"].to_list()

flows = []

for i in range(1,50):
    temp = str.split(data[i], "-")
    flows.append([temp[0],temp[1]])


df2 = pd.DataFrame(flows)

G = nx.Graph()
G.add_nodes_from(df2[0])
G.add_nodes_from(df2[1])
G.add_edges_from(flows)


nx.draw_networkx(G)
nx.draw_shell(G, with_labels=True)