import os, csv, re, ipaddress
import xml.etree.ElementTree as ET
import networkx as nx
from subnets import Subnet, Subnets, Host
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

try:
    from networkx.drawing.nx_agraph import graphviz_layout
except ImportError:
    from networkx.drawing.nx_pydot import graphviz_layout

def draw_topology(devices, connections):
    import pygraphviz as pgv
    from collections import defaultdict

    G = nx.DiGraph()
    for device in devices:
        G.add_node(device["ip"])
    G.add_edges_from(connections)

    A = nx.nx_agraph.to_agraph(G)
    A.graph_attr.update({
        'ranksep': '1.5',
        'dpi': '300'
    })

    subnet_nodes = defaultdict(list)
    subnet_colors = {}
    pastel_colors = [
        color for name, color in mcolors.CSS4_COLORS.items()
        if any(word in name for word in ['light', 'honeydew', 'mint', 'lavender', 'alice', 'beige', 'linen'])
    ]

    if not pastel_colors:
        pastel_colors = ['#f0f8ff', '#e6f2ff', '#f5f5dc', '#f0fff0', '#fffaf0', '#fdf5e6']

    for device in devices:
        subnet = device.get("subnet", "unknown")
        subnet_nodes[subnet].append(device)

    for i, (subnet, dev_list) in enumerate(subnet_nodes.items()):
        color = pastel_colors[i % len(pastel_colors)]
        subnet_colors[subnet] = color

        sg = A.add_subgraph(
            name=f"cluster_{i}",
            label=f"{subnet}",
            style="filled",
            color="gray",
            fillcolor=color
        )

        for device in dev_list:
            ip = device["ip"]
            image = "images/router.png" if ip == "0.0.0.0" or ip.endswith(".1") else "images/pc.png"
            label = f'''<<TABLE BORDER="0" CELLBORDER="0">
  <TR><TD><IMG SRC="{image}" SCALE="TRUE"/></TD></TR>
  <TR><TD><FONT POINT-SIZE="14">{ip}</FONT></TD></TR>
</TABLE>>'''
            sg.add_node(ip, shape="none", label=label)

    for src, dst in connections:
        A.add_edge(src, dst)

    A.layout(prog="dot")
    A.draw("network_topology.png")
    print("✅ Diagram saved as 'network_topology.png'")

def print_subnets(subs: Subnets):
    for subnet in subs.subnet_list:
        print(f'\nSubnet: {subnet.subnet}')
        print(f'gateway: {subnet.gateway}')
        for host in subnet.hosts:
            print(f'Hostname: {host.hostname} - {host.ip}')
        print('\n')

# === MAIN ENTRYPOINT ===
if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    folder = os.getenv("SCAN_FOLDER")
    if not folder or not os.path.exists(folder):
        raise ValueError("❌ SCAN_FOLDER is not set or doesn't exist.")
    subnets = Subnets()
    for filename in os.listdir(folder):
        if filename.endswith(".xml"):
            xml_path    = os.path.join(folder, filename)
            subnet      = Subnet.from_nmap_xml(xml_path)
            subnets.add_subnet(subnet)
        if filename.endswith(".csv"):
            csv_path    = os.path.join(folder, filename)
            subnet      = Subnet.from_csv(csv_path)
            subnets.add_subnet(subnet)
    print_subnets(subnets)
    devices, connections = subnets.devices_and_connections()
    draw_topology(devices=devices, connections=connections)
