import subprocess
import shutil


def pcap_to_json(pcap_file):
    # Trouve le chemin de tshark compatible tous OS
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        raise RuntimeError("❌ Tshark n'est pas installé ou non détecté dans le PATH.")

    tshark_command = [
        tshark_path, "-r", pcap_file, "-Y", "tls.handshake.type == 11", "-T", "fields",
        "-e", "ip.src", "-e", "x509sat.CountryName"
    ]

    try:
        result = subprocess.run(tshark_command, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split("\n")
        certificate_info = {}
        for line in lines:
            fields = line.split("\t")
            if len(fields) >= 2:
                ip_src = fields[0]
                country = ','.join(sorted(set(fields[1].split(','))))
                countries = country.split(',') if len(country) > 2 else [country]

                for c in countries:
                    if c not in certificate_info:
                        certificate_info[c] = set()
                    certificate_info[c].add(ip_src)

        return {country: list(ips) for country, ips in certificate_info.items()}

    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'exécution de TShark: {e}")
        return {}
