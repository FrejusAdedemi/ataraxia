
# Ataraxia

Ataraxia est une application de cybersécurité développée dans le cadre du projet IT-GAME. Elle permet d'analyser des fichiers PCAP pour détecter des activités malveillantes telles que le scan de ports, les attaques par force brute et les connexions suspectes. L'interface web fournit une visualisation claire des menaces détectées, facilitant ainsi l'analyse et la prise de décision.

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Structure du projet](#structure-du-projet)
- [Technologies utilisées](#technologies-utilisées)



## Fonctionnalités

- Analyse de fichiers PCAP pour détecter :
  - Scans de ports
  - Attaques par force brute
  - Connexions suspectes
  - Malwares
  - Certificats auto-signés
- Interface web interactive affichant :
  - Tableau des malwares détectés
  - Liste des IPs suspectes avec leur score de menace
  - Détails des tentatives d'accès privées et publiques
  - Carte géographique des connexions
- Génération de rapports pour une analyse approfondie

## Prérequis

- Python 3.12
- pip
- Environnement virtuel (recommandé)

## Installation

1. Clonez le dépôt :

   ```bash
   git clone https://github.com/votre-utilisa/ataraxia.git
   cd ataraxia
   ```

2. Créez et activez un environnement virtuel :

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Sur Windows : .venv\Scripts\activate
   ```

3. Installez les dépendances :

   ```bash
   pip install -r requirements.txt
   ```

## Utilisation

1. Lancez le serveur Flask :

   ```bash
   python app.py
   ```

2. Ouvrez votre navigateur à l'adresse : [http://127.0.0.1:5000](http://127.0.0.1:5000)

3. Chargez un fichier PCAP pour démarrer l'analyse.

## Structure du projet

```bash
vyrolock/
├── app.py
├── static/
│   ├── style.css
│   ├── script.js
│   └── logo.png
├── templates/
│   └── index.html
├── pcap/
│   └── ex4.pcap
├── README.md
├── .gitignore
└── requirements.txt
```

## Technologies utilisées

- **Backend** : Flask
- **Frontend** : HTML, CSS, JavaScript
- **Analyse de paquets** : Scapy
- **Visualisation** : Leaflet.js pour la carte interactive
- **Autres** : pandas, json, etc.
