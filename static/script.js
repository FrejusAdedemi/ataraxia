document.addEventListener("DOMContentLoaded", () => {
  const attackObject = [
    { brutforce: 0 },
    { analysePort: 0 },
  ];
  let globalIp = "";

  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };

  fetch("/malware")
    .then((res) => res.json())
    .then((data) => {
      const body = document.querySelector("#malware-table tbody");
      Object.entries(data).forEach(([ip, { malware }]) => {
        const row = document.createElement("tr");
        row.innerHTML = `<td>${ip}</td><td>${malware}</td>`;
        body.appendChild(row);
      });
    })
    .catch((err) => console.error("Malware ❌:", err));

  fetch("/suspicious")
    .then((res) => res.json())
    .then((data) => {
      const sorted = Object.entries(data).sort(
        (a, b) => b[1].threat_score - a[1].threat_score
      );
      const body = document.querySelector("#suspicious-table tbody");
      sorted.forEach(([ip, { state, threat_score }]) => {
        const row = document.createElement("tr");
        row.innerHTML = `<td>${ip}</td><td>${state}</td><td>${threat_score}</td>`;
        body.appendChild(row);
      });
    })
    .catch((err) => console.error("Suspicious ❌:", err));

  fetch("/init_access")
    .then((res) => res.json())
    .then((data) => {
      if (!data.initial_access || !Array.isArray(data.initial_access)) {
        throw new Error("Données d'accès initial manquantes");
      }

      const first = data.initial_access[0];
      globalIp = first.ip;

      setText("ip", `IP: ${first.ip}`);
      setText("mac", `MAC: ${first.mac_address}`);
      setText("machine", `Nom Machine: ${first.nom_machine}`);
      setText("user", `Utilisateur: ${first.nom_utilisateur}`);
      setText("flag", `Flag: ${data.message}`);

      return fetch(`/private_access/${globalIp}`);
    })
    .then((res) => res.json())
    .then((data) => {
      const tentatives = Array.isArray(data.tentatives_dacces_entre_ips_privees)
        ? data.tentatives_dacces_entre_ips_privees
        : Object.values(data.tentatives_dacces_entre_ips_privees || {});

      const body = document.querySelector("#tentatives-table tbody");

      tentatives.forEach((entry) => {
        if (entry.ports.length >= 40) attackObject[1].analysePort = 1;
        if (entry.nb_tentatives >= 100) attackObject[0].brutforce = 1;

        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${entry.src_ip}</td>
          <td>${entry.dst_ip}</td>
          <td>${entry.nb_tentatives}</td>
          <td>${entry.protocols}</td>
          <td>${entry.ports}</td>
        `;
        body.appendChild(row);
      });

      return fetch(`/public_access/${globalIp}`);
    })
    .then((res) => res.json())
    .then((data) => {
      const body = document.querySelector("#public-tentatives-table");
      Object.entries(data).forEach(([ip, entry]) => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${globalIp}</td>
          <td>${ip}</td>
          <td>${entry.nb_tentatives}</td>
          <td>${entry.ports.join(", ")}</td>
        `;
        body.appendChild(row);
      });

      const attackTable = document.querySelector("#attack-table");
      attackObject.forEach((entry) => {
        const row = document.createElement("tr");
        if (entry.analysePort === 1) {
          row.innerHTML = `<td>Analyse de ports</td>`;
        } else if (entry.brutforce === 1) {
          row.innerHTML = `<td>Bruteforce</td>`;
        } else {
          return;
        }
        attackTable.appendChild(row);
      });
    })
    .catch((err) => console.error("Initial Access & Connexions ❌:", err));

  // Carte Leaflet + Certificats auto-signés
  const mapContainer = document.getElementById("map");
  if (mapContainer) {
    const map = L.map("map").setView([0, 0], 2);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
    }).addTo(map);

    const certTable = document.querySelector("#cert-table");

   fetch("/map")
  .then((res) => res.json())
  .then((data) => {
    const certTable = document.querySelector("#cert-table");
    let hasAuto = false;

    // data est un objet { "AZ": [ip1, ip2], "TJ": [ip1], ... }
    Object.entries(data).forEach(([country, ips]) => {
      // Affichage sur la carte (si tu as des coordonnées associées plus tard)
      // ici tu peux faire un appel à une API comme https://restcountries.com pour latitude/longitude
      // Par défaut, on place un marqueur fictif (à adapter)
      const fakeLatLng = [Math.random() * 140 - 70, Math.random() * 360 - 180];
      L.marker(fakeLatLng)
        .addTo(map)
        .bindPopup(`${country}: ${ips.length} IP(s)`);

      // Gestion des certificats auto-signés
      if (country === "inconnu") {
        hasAuto = true;
        ips.forEach((ip) => {
          const row = document.createElement("tr");
          row.innerHTML = `<td>${ip}</td>`;
          certTable.appendChild(row);
        });
      }
    });

    if (!hasAuto) {
      const row = document.createElement("tr");
      row.innerHTML = `<td>Aucun certificat auto-signé</td>`;
      certTable.appendChild(row);
    }
  })
  .catch((err) => console.error("Carte Leaflet ❌:", err));

