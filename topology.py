import os
import csv
import re
import ipaddress
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

try:
    from networkx.drawing.nx_agraph import graphviz_layout
except ImportError:
    from networkx.drawing.nx_pydot import graphviz_layout


def get_private_ips_from_csv(path):
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    private_ips = set()

    with open(path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            for cell in row:
                matches = ip_pattern.findall(cell)
                for ip in matches:
                    try:
                        ip_obj = ipaddress.IPv4Address(ip)
                        if ip_obj.is_private:
                            private_ips.add(ip)
                    except ValueError:
                        continue

    return private_ips


def gather_all_ips(folder_path):
    subnet_groups = {}  # subnet -> list of IPs

    for filename in os.listdir(folder_path):
        if filename.endswith(".csv"):
            csv_path = os.path.join(folder_path, filename)
            ips = get_private_ips_from_csv(csv_path)
            for ip in ips:
                subnet = ".".join(ip.split('.')[:3]) + ".0/24"
                subnet_groups.setdefault(subnet, set()).add(ip)

    return subnet_groups

def build_devices_and_connections(subnet_groups):
    devices = []
    connections = []
    all_ips = set()
    subnet_colors = {}
    color_list = list(mcolors.TABLEAU_COLORS.values()) + list(mcolors.CSS4_COLORS.values())

    for index, (subnet, ips) in enumerate(subnet_groups.items()):
        color = color_list[index % len(color_list)]
        subnet_colors[subnet] = color

        gateway = subnet.replace('0/24', '1')
        if gateway not in ips:
            ips.add(gateway)  # Add gateway if not found

        for ip in ips:
            devices.append({"ip": ip, "subnet": subnet, "color": color})
            all_ips.add(ip)

        # Link devices to gateway
        for ip in ips:
            if ip == gateway:
                connections.append(("0.0.0.0", ip))  # root -> gateway
            else:
                connections.append((gateway, ip))

    # Add root device if needed
    devices.insert(0, {"ip": "0.0.0.0", "subnet": "Internet", "color": "#bbbbbb"})
    return devices, connections


def draw_topology(devices, connections):
    import pygraphviz as pgv
    import networkx as nx
    from collections import defaultdict
    import matplotlib.colors as mcolors

    # Build graph
    G = nx.DiGraph()
    for device in devices:
        G.add_node(device["ip"])
    G.add_edges_from(connections)

    A = nx.nx_agraph.to_agraph(G)
    A.graph_attr.update({
        'ranksep': '1.5',
        'dpi': '300'
    })

    # Assign soft background colors to subnets
    subnet_nodes = defaultdict(list)
    subnet_colors = {}
    pastel_colors = [
        color for name, color in mcolors.CSS4_COLORS.items()
        if any(word in name for word in ['light', 'honeydew', 'mint', 'lavender', 'alice', 'beige', 'linen'])
    ]

    if not pastel_colors:
        pastel_colors = ['#f0f8ff', '#e6f2ff', '#f5f5dc', '#f0fff0', '#fffaf0', '#fdf5e6']  # Fallbacks

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

    # Add edges manually
    for src, dst in connections:
        A.add_edge(src, dst)

    A.layout(prog="dot")
    A.draw("network_topology.png")
    print("Saved diagram as 'network_topology.png' with colored subnet groups and styled icons")


# === MAIN ENTRYPOINT ===
if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    folder = os.getenv("SCAN_FOLDER")
    if not folder or not os.path.exists(folder):
        raise ValueError("SCAN_FOLDER is not set correctly in .env or the folder does not exist.")

    subnet_groups = gather_all_ips(folder)
    devices, connections = build_devices_and_connections(subnet_groups)
    draw_topology(devices, connections)

