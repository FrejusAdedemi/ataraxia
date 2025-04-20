FROM python:3.12-slim

# Évite les invites interactives lors de l'installation
ENV DEBIAN_FRONTEND=noninteractive

# Installation de tshark et des dépendances nécessaires
RUN apt-get update && apt-get install -y \
    tshark \
    libpcap-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Définition du répertoire de travail
WORKDIR /app

# Copie des fichiers du projet
COPY . /app

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Exposition du port utilisé par Flask
EXPOSE 8080

# Commande pour démarrer l'application
CMD ["python", "app.py"]
