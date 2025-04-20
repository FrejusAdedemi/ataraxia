import subprocess
import os
import requests
import shutil
from modules.config import USE_REMOTE_SERVER

def download_file(dest_folder: str = "./pcap") -> str:
    os.makedirs(dest_folder, exist_ok=True)

    fallback_file = "ex4.pcap"
    fallback_path = os.path.join(dest_folder, fallback_file)

    if not USE_REMOTE_SERVER:
        print("🔁 Fallback sur un fichier local : ex4.pcap")
        print(f"📦 Utilisation de {fallback_path}")
        if os.path.exists(fallback_path):
            return fallback_path
        else:
            raise RuntimeError("❌ Aucun fichier pcap disponible. Le fallback 'ex4.pcap' est introuvable.")

    url = "http://93.127.203.48:5000/pcap/latest"
    url_filename = url + "/filename"

    try:
        response = requests.get(url_filename, timeout=5)
        response.raise_for_status()
        filename = response.json().get("filename")
        file_path = os.path.join(dest_folder, filename)

        if os.path.exists(file_path):
            print(f"📦 Fichier déjà présent : {file_path}")
            return file_path

        subprocess.run(["curl", "-OJ", "-sL", "-o", file_path, url], check=True)
        return file_path

    except Exception as e:
        print("⚠️ Erreur de téléchargement distant :", e)
        print("🔁 Fallback sur un fichier local : ex4.pcap")
        if os.path.exists(fallback_path):
            print(f"📦 Utilisation de {fallback_path}")
            return fallback_path
        else:
            raise RuntimeError("❌ Aucun fichier pcap disponible. Le fallback 'ex4.pcap' est introuvable.")
