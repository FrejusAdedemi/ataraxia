from modules.map_generator import load_country_codes, extract_country_code, get_country_name, add_country_pins, save_map_with_js_style
from scapy.all import rdpcap, IP, TCP, UDP, Raw

def extract_info(packet):
    """Extraction des informations réseau importantes d'un paquet"""
    data = {}
    
    if packet.haslayer(IP):
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst
        data["timestamp"] = packet.time
        if packet.haslayer(TCP):
            data["port"] = packet[TCP].dport
        elif packet.haslayer(UDP):
            data["port"] = packet[UDP].dport
        else:
            data["port"] = None

        if packet.haslayer(Raw):
            data["payload"] = packet[Raw].load.decode(errors="ignore")
        else:
            data["payload"] = ""
        return data
    return None

def extract_country(ip, country_codes):
    """Extrait le pays à partir de l'IP en utilisant les codes pays"""
    country_code = extract_country_code(ip, country_codes)
    return get_country_name(country_code,country_codes)

def map_generator(filename):
    country_codes = load_country_codes()
    packets = rdpcap(filename)
    
    # Créer un dictionnaire pour les IPs et pays
    country_info = {}

    for packet in packets:
        packet_info = extract_info(packet)
        if packet_info:
            ip_src = packet_info["src_ip"]
            country = extract_country(ip_src, country_codes)
            
            # Réduire la clé (pays) à une seule occurrence
            country = ','.join(sorted(set(country.split(','))))  # Réduire les répétitions de pays

            if country not in country_info:
                country_info[country] = set()  # Créer un set pour chaque pays
            country_info[country].add(ip_src)  # Ajouter l'IP au set

    # Reformatage : chaque pays avec ses IPs uniques
    formatted_info = {}
    for country, ips in country_info.items():
        formatted_info[country] = list(ips)  # Convertir le set en liste

    add_country_pins(formatted_info, country_codes)
    save_map_with_js_style()
    
    return formatted_info
