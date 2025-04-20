import subprocess
import json
import ipaddress

def public_access(pcap_file, ip_src):
    def is_public_ip(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not ip_obj.is_private
        except ValueError:
            return False

    command = [
        "tshark", "-r", pcap_file, "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto", "-e", "tcp.port", "-e", "udp.port"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError("Erreur lors de l'exécution de tshark.")
    
    connections = {}
    for packet in result.stdout.splitlines():
        fields = packet.split("\t")
        if len(fields) < 4:
            continue

        src_ip, dst_ip, protocol, port_field = fields[0], fields[1], fields[2], fields[3] if len(fields) > 3 else None
        if src_ip == ip_src and is_public_ip(dst_ip):
            if dst_ip not in connections:
                connections[dst_ip] = {"nb_tentatives": 0, "ports": set()}
            
            connections[dst_ip]["nb_tentatives"] += 1
            if port_field:
                connections[dst_ip]["ports"].update(port_field.split(","))
    
    for dst_ip in connections:
        connections[dst_ip]["ports"] = sorted(connections[dst_ip]["ports"], key=int)
    
    return connections
