# Test minimal de l'API NVD. On vérifie le code de réponse et la durée d'un seul appel.
import time
import requests

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Les dates doivent toujours aller par paire (début et fin). Ici une seule journée.
params = {
    "pubStartDate": "2026-10-14T00:00:00.000",
    "pubEndDate": "2026-10-14T23:59:59.999",
    "resultsPerPage": 1,
}

debut = time.perf_counter()
reponse = requests.get(URL, params=params, timeout=30)
duree = time.perf_counter() - debut

print("Code de réponse :", reponse.status_code)
print("Durée (secondes) :", round(duree, 2))
print("Début de l'URL appelée :", reponse.url[:120])

# On lit le contenu uniquement si l'appel a réussi.
if reponse.status_code == 200:
    donnees = reponse.json()
    print("Total de failles ce jour-là :", donnees.get("totalResults"))
    print("Failles reçues dans cette page :", len(donnees.get("vulnerabilities", [])))