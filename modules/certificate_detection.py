import subprocess

def pcap_to_json(pcap_file):
    # Commande TShark pour extraire l'IP source et les pays des certificats TLS
    tshark_command = [
        r"C:\Program Files\Wireshark\tshark.exe", "-r", pcap_file, "-Y", "tls.handshake.type == 11", "-T", "fields", 
        "-e", "ip.src", "-e", "x509sat.CountryName"
    ]

    try:
        # Exécution de la commande
        result = subprocess.run(tshark_command, capture_output=True, text=True, check=True)
        
        # Traitement des résultats pour associer les IPs aux informations des certificats
        lines = result.stdout.strip().split("\n")
        certificate_info = {}
        for line in lines:
            fields = line.split("\t")
            if len(fields) >= 2:
                ip_src = fields[0]  # IP source
                country = fields[1]  # Pays
                
                # Réduire la clé (pays) à une seule occurrence
                country = ','.join(sorted(set(country.split(','))))  # Réduire les répétitions de pays

                if len(country) > 2:
                # Utiliser un set pour éviter les doublons d'IP pour un même pays
                    countries = country.split(',')
                    for country in countries:
                        if country not in certificate_info:
                            certificate_info[country] = set()  # Créer un set pour chaque pays
                        certificate_info[country].add(ip_src)
                else:
                    if country not in certificate_info:
                        certificate_info[country] = set()  # Créer un set pour chaque pays
                    certificate_info[country].add(ip_src)  # Ajouter l'IP au set

        # Reformatage : chaque pays avec ses IPs uniques
        formatted_info = {}
        for country, ips in certificate_info.items():
            formatted_info[country] = list(ips)  # Convertir le set en liste

        return formatted_info
    
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'exécution de TShark: {e}")
        return None
