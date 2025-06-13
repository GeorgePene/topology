import ipaddress, re, csv
from dataclasses import dataclass
from typing import Optional, List
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None

@dataclass
class Subnet:
    subnet: str
    gateway: Optional[str] = None
    hosts: List[Host] = field(default_factory=list)

    @classmethod
    def from_nmap_xml(cls, xml_file: str) -> 'Subnet':
        tree = ET.parse(xml_file)
        root = tree.getroot()
        hosts = []

        # --- Extract subnet from args ---
        args = root.attrib.get("args", "")
        subnet_match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", args)
        subnet_str = subnet_match.group(1) if subnet_match else "0.0.0.0/0"
        net = ipaddress.ip_network(subnet_str, strict=False)

        # --- Gather IPs from Nmap scan ---
        alive_ips = set()
        for host_elem in root.findall('host'):
            ip = None
            hostname = None

            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            if addr_elem is not None:
                ip = addr_elem.get('addr')
                alive_ips.add(ip)

            hostname_elem = host_elem.find('hostnames/hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name')

            if ip:
                hosts.append(Host(ip=ip, hostname=hostname))

        # --- Determine gateway: first usable IP if it's alive ---
        gateway = str(list(net.hosts())[0])  # First usable IP

        # --- Sort hosts for consistency ---
        sorted_hosts = sorted(hosts, key=lambda h: ipaddress.ip_address(h.ip))

        return cls(subnet=subnet_str, gateway=gateway, hosts=sorted_hosts)

    @classmethod
    def from_csv(cls, csv_path: str) -> 'Subnet':
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        private_ips = set()

        with open(csv_path, newline='', encoding='utf-8') as csvfile:
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

        if not private_ips:
            raise ValueError("No private IPs found in CSV.")

        # Pick the most common /24 subnet from the private IPs
        networks = [ipaddress.ip_network(f"{ip}/24", strict=False) for ip in private_ips]
        most_common_net = max(set(networks), key=networks.count)
        subnet_str = str(most_common_net)

        # First usable IP as gateway
        gateway = str(list(most_common_net.hosts())[0])

        hosts = [Host(ip=ip) for ip in sorted(private_ips, key=lambda ip: ipaddress.ip_address(ip))]

        return cls(subnet=subnet_str, gateway=gateway, hosts=hosts)

    def to_dict(self) -> dict:
        return {self.subnet: {f"{host.ip} {host.hostname or ''}" for host in self.hosts}}

class Subnets:
    def __init__(self):
        self.subnet_list = []

    def add_subnet(self, subnet: Subnet):
        self.subnet_list.append(subnet)

    def merged_dict(self) -> dict:
        merged = {}
        for subnet in self.subnet_list:
            subnet_dict = subnet.to_dict()
            for key, value in subnet_dict.items():
                if key in merged:
                    merged[key].update(value)
                else:
                    merged[key] = set(value)
        return merged

    def devices_and_connections(self):
        subnet_groups = self.merged_dict()
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
                ips.add(gateway)

            for ip in ips:
                devices.append({"ip": ip.strip(), "subnet": subnet, "color": color})
                all_ips.add(ip)

            for ip in ips:
                ip = ip.strip()
                if ip == gateway:
                    connections.append(("0.0.0.0", ip))
                else:
                    connections.append((gateway, ip))

        devices.insert(0, {"ip": "0.0.0.0", "subnet": "Internet", "color": "#bbbbbb"})
        return devices, connections

