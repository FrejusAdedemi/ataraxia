import subprocess
import json
import shutil
import requests
from modules.return_file import download_file


def parse_tshark_output(pcap_file):
    # ✅ Vérifie que tshark est installé
    if not shutil.which("tshark"):
        return {"error": "❌ tshark n'est pas installé ou pas dans le PATH."}

    command = [
        "tshark", "-r", pcap_file, "-Y", "http.request",
        "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "http.request.uri"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        data = []
        for line in result.stdout.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) == 3 and parts[2] != "*":
                entry = {
                    "ip_src": parts[0],
                    "ip_dst": parts[1],
                    "file_requested": parts[2]
                }
                data.append(entry)
        return data

    except subprocess.CalledProcessError as e:
        return {"error": "Erreur lors de l'exécution de tshark", "details": str(e)}


def analyze_malware(pcap_file):
    data = parse_tshark_output(pcap_file)
    if isinstance(data, dict) and "error" in data:
        print("Erreur malware:", data["error"])
        return data  # retourne l’erreur directement

    malware_analyze = {}
    for result in data:
        ip_dst = result["ip_dst"]
        try:
            analysis_api = f"http://127.0.0.1:5000/threat_score/{ip_dst}"
            response = requests.get(analysis_api, timeout=5)
            response.raise_for_status()
            results = response.json()
            if results:
                malware_analyze[ip_dst] = {"malware": result["file_requested"]}
        except Exception as e:
            malware_analyze[ip_dst] = {"error": str(e)}

    return malware_analyze

# if __name__ == "__main__":
#     from return_file import download_file
#     pcap_file = download_file()
#     result = analyze_malware(pcap_file)
#     print(json.dumps(result, indent=2))
