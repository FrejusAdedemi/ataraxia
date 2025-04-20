import folium
import json

# Position [latitude, longitude] sur laquelle est centrée la carte
location = [47, 1]

# Niveau de zoom initial : 
# 3-4 pour un continent, 5-6 pour un pays, 11-12 pour une ville
zoom = 6

# Style de la carte
tiles = 'cartodb positron'

# Créer la carte
carte = folium.Map(location=location, zoom_start=zoom, tiles=tiles)

added_countries = set()

def add_pin_to_map(country_name, latitude, longitude):
    """Ajoute une épingle sur la carte à la latitude et longitude données"""
    if country_name not in added_countries:
        folium.Marker([latitude, longitude], popup=country_name, icon=folium.Icon(color='blue', icon_color='white', icon='cloud'),).add_to(carte)
        added_countries.add(country_name)

def save_map_with_js_style():
    carte.save("./templates/carte_interactive.html")
    with open("./templates/carte_interactive.html", "r") as file:
        html_content = file.read()

    # Ajouter un script JavaScript pour cibler l'élément de la carte et modifier son style
    js_script = """
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Cibler l'élément dont l'id commence par 'map_'
        var mapElement = document.querySelector('[id^="map_"]');
        
        if (mapElement) {
            // Modifier le style CSS de la carte
            mapElement.style.width = '50%'; // 80% de la largeur de la page
            mapElement.style.height = '70vh'; // 70% de la hauteur de la fenêtre
            mapElement.style.margin = '0 auto'; // Centrer horizontalement
            mapElement.style.border = '2px solid #000'; // Ajouter une bordure noire autour de la carte
        }
    });
    </script>
    """

    # Ajouter le script JavaScript avant la fin de la balise </body>
    html_content = html_content.replace("</body>", js_script + "</body>")

    # Sauvegarder le fichier HTML modifié en écrasant l'original
    with open("./templates/carte_interactive.html", "w") as file:
        file.write(html_content)

# Charger Iso pays 
def load_country_codes(filename="countryCode.json"):
    """Charge la liste des pays avec leurs codes ISO."""
    with open(filename, "r", encoding="utf-8") as file:
        data = json.load(file)
        return data["ref_country_codes"]

# ajout épingles carte
def add_country_pins(filtered_packets, country_codes):
    for packet_data in filtered_packets:
        country_code = extract_country_code(packet_data["payload"], country_codes)
        if country_code:
            country_name, latitude, longitude = get_country_name(country_code, country_codes)
            print(f"Pays : {country_name} (Code ISO : {country_code})")
            
            if latitude and longitude:
                add_pin_to_map(country_name, latitude, longitude)

def extract_country_code(payload, country_codes):
    """Extrait le code ISO à 2 lettres d'un certificat contenu dans un payload."""
    for country in country_codes:
        if country["alpha2"].lower() in payload.lower():
            return country["alpha2"]
    return None

def get_country_name(country_code, country_codes):
    """Récupère le nom du pays à partir du code ISO à 2 lettres."""
    for country in country_codes:
        if country["alpha2"] == country_code:
            return country["country"], country["latitude"], country["longitude"]
    return "Unknown", None, None

# Sauvegarder la carte finale
save_map_with_js_style()

def extract_ip_info(packets):
    """
    Extrait les IP source et destination depuis les paquets analysés.
    :param packets: Liste de dictionnaires représentant les paquets
    :return: Liste de tuples (ip_src, ip_dst)
    """
    ip_pairs = []
    for packet in packets:
        ip_src = packet.get("ip_src")
        ip_dst = packet.get("ip_dst")
        if ip_src and ip_dst:
            ip_pairs.append((ip_src, ip_dst))
    return ip_pairs
