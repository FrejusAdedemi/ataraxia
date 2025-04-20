import subprocess
import json
import ipaddress

ALERT_THRESHOLD = 10  # Seuil d'alerte pour identifier un scan massif

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def extract_packets(pcap_file):
    command = [
        r"C:\Program Files\Wireshark\tshark.exe", "-r", pcap_file, "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto", "-e", "tcp.port", "-e", "udp.port", "-e", "icmp.type"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Erreur lors de l'exécution de tshark.")
        return []
    
    return result.stdout.splitlines()

def detect_private_network_scanning(packets, specific_src_ip):
    scanning_attempts = {}
    
    for packet in packets:
        fields = packet.split("\t")
        if len(fields) < 4:
            continue
        
        src_ip, dst_ip = fields[:2]
        if src_ip != specific_src_ip:
            continue
        
        protocol = fields[2]
        tcp_port = fields[3] if len(fields) > 3 else ""
        udp_port = fields[4] if len(fields) > 4 else ""
        icmp_type = fields[5] if len(fields) > 5 else ""
        
        if is_private_ip(src_ip) and is_private_ip(dst_ip):
            if src_ip not in scanning_attempts:
                scanning_attempts[src_ip] = {}
            if dst_ip not in scanning_attempts[src_ip]:
                scanning_attempts[src_ip][dst_ip] = {"nb_tentatives": 0, "ports": set(), "protocols": set()}
            
            scanning_attempts[src_ip][dst_ip]["nb_tentatives"] += 1
            
            if tcp_port:
                scanning_attempts[src_ip][dst_ip]["ports"].add(tcp_port.strip())
            if udp_port:
                scanning_attempts[src_ip][dst_ip]["ports"].add(udp_port.strip())
            
            if protocol == "1" and icmp_type == "8":
                scanning_attempts[src_ip][dst_ip]["protocols"].add("ICMP (Ping)")
            elif protocol == "6":
                scanning_attempts[src_ip][dst_ip]["protocols"].add("TCP")
            elif protocol == "17":
                scanning_attempts[src_ip][dst_ip]["protocols"].add("UDP")
    
    for src_ip in scanning_attempts:
        for dst_ip in scanning_attempts[src_ip]:
            scanning_attempts[src_ip][dst_ip]["ports"] = sorted(
                {int(port) for port in ",".join(scanning_attempts[src_ip][dst_ip]["ports"]).split(",") if port.isdigit()}
            )
            scanning_attempts[src_ip][dst_ip]["protocols"] = list(scanning_attempts[src_ip][dst_ip]["protocols"])
    
    return scanning_attempts

def format_to_json(scanning_attempts):
    formatted_results = []
    for src_ip, dst_ips in scanning_attempts.items():
        for dst_ip, data in dst_ips.items():
            formatted_results.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "nb_tentatives": data["nb_tentatives"],
                "ports": ",".join(map(str, data["ports"])),
                "protocols": ", ".join(data["protocols"])
            })
    return json.dumps(formatted_results, indent=4)

def detect_suspicious_ips(scanning_attempts):
    suspicious_ips = []
    for src_ip, dst_ips in scanning_attempts.items():
        if len(dst_ips) >= ALERT_THRESHOLD:
            suspicious_ips.append({
                "ip_suspecte": src_ip,
                "nombre_cibles": len(dst_ips),
                "destinations": list(dst_ips.keys())
            })
    return json.dumps(suspicious_ips, indent=4)

def analyze_pcap_and_ip(pcap_file, specific_src_ip):
    packets = extract_packets(pcap_file)
    scanning_attempts = detect_private_network_scanning(packets, specific_src_ip)
    result_json = format_to_json(scanning_attempts)
    suspicious_ips_json = detect_suspicious_ips(scanning_attempts)
    
    return {
        "tentatives_dacces_entre_ips_privees": json.loads(result_json),
        "ips_suspectes_detectees": json.loads(suspicious_ips_json)
    }
