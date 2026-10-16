# ______________________________________________________________
# TÉLÉCHARGEMENT POUR L'EXPLORATION (CSV)
# ______________________________________________________________

import time
import requests
from datetime import datetime, timedelta, timezone

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ______________________________________________________________
# FONCTION D'APPEL (copie de script_v1.py)
# ______________________________________________________________

# Appelle l'API et réessaie après une attente si le serveur a un souci.
def appeler_api(params, max_essais=4, attente_base=6):
    for essai in range(1, max_essais + 1):
        try:
            reponse = requests.get(URL, params=params, timeout=30)
        except requests.exceptions.Timeout:
            raison = "délai dépassé"
        except requests.exceptions.ConnectionError:
            raison = "connexion impossible"
        else:
            code = reponse.status_code
            if code == 200:
                return reponse.json()
            elif code in (403, 429):
                raison = f"limite atteinte (code {code})"
            elif code >= 500:
                raison = f"serveur indisponible (code {code})"
            else:
                # Mauvaise requête, réessayer ne servirait à rien.
                message_api = reponse.headers.get("message", "aucun message de l'API")
                raise ValueError(f"Erreur de requête (code {code}) : {message_api}")

        # Ici l'essai a raté pour une raison qui vaut le coup de réessayer.
        if essai < max_essais:
            attente = attente_base * essai
            print(f"Essai {essai}/{max_essais} raté, {raison}. Nouvel essai dans {attente} s.")
            time.sleep(attente)
        else:
            raise RuntimeError(f"Échec après {max_essais} essais, dernière raison : {raison}")


# ______________________________________________________________
# ÉTAPE 7a : comptage des failles par tranche
# ______________________________________________________________

# -- Met une date au format attendu par l'API (millisecondes sur 3 chiffres)
def formater_date(date):
    return date.strftime("%Y-%m-%dT%H:%M:%S.") + f"{date.microsecond // 1000:03d}"


# -- Découpe la période en tranches de 100 jours maximum
def decouper_periode(debut, fin, jours_max=100):
    tranches = []
    courant = debut
    while courant < fin:
        suivant = min(courant + timedelta(days=jours_max), fin)
        tranches.append((courant, suivant))
        courant = suivant
    return tranches


# # -- La période va du 1er octobre 2025 à maintenant (heure UTC)
# debut_periode = datetime(2025, 10, 1)
# fin_periode = datetime.now(timezone.utc).replace(tzinfo=None)
# tranches = decouper_periode(debut_periode, fin_periode)
# print("Nombre de tranches :", len(tranches))


# # -- Compte les failles de chaque tranche sans rien télécharger
# total_general = 0
# for numero, (debut, fin) in enumerate(tranches, start=1):
#     fin_inclusive = fin - timedelta(milliseconds=1) if fin != fin_periode else fin
#     params = {
#         "pubStartDate": formater_date(debut),
#         "pubEndDate": formater_date(fin_inclusive),
#         "resultsPerPage": 1,
#     }
#     donnees = appeler_api(params)
#     total = donnees["totalResults"]
#     total_general += total
#     print(f"Tranche {numero} : {params['pubStartDate']} -> {params['pubEndDate']} : {total} failles")
#     time.sleep(6)

# print("Total sur la période :", total_general)

# ______________________________________________________________
# ÉTAPE 7b : tables produits_touches et faiblesses (test sur une journée)
# ______________________________________________________________

from collections import Counter
import pandas as pd


# -- Une ligne par produit touché (deux boucles car deux listes imbriquées)
def extraire_produits(fiche):
    cve = fiche["cve"]
    lignes = []
    for bloc in cve.get("affected", []):
        for produit in bloc.get("affectedData", []):
            lignes.append({
                "cve_id": cve.get("id"),
                "vendor": produit.get("vendor"),
                "product": produit.get("product"),
            })
    return lignes


# -- Une ligne par faiblesse (type de défaut) de chaque faille
def extraire_faiblesses(fiche):
    cve = fiche["cve"]
    lignes = []
    for faiblesse in cve.get("weaknesses", []):
        for description in faiblesse.get("description", []):
            lignes.append({
                "cve_id": cve.get("id"),
                "cwe": description.get("value"),
            })
    return lignes


# -- On récupère la journée du 14 octobre en un seul appel
params_jour = {
    "pubStartDate": "2026-10-14T00:00:00.000",
    "pubEndDate": "2026-10-14T23:59:59.999",
    "resultsPerPage": 2000,
}
fiches = appeler_api(params_jour)["vulnerabilities"]
print("Failles reçues :", len(fiches))


# -- Construit les deux tables
table_produits = pd.DataFrame([l for f in fiches for l in extraire_produits(f)])
table_faiblesses = pd.DataFrame([l for f in fiches for l in extraire_faiblesses(f)])


# -- Regard sur produits_touches
print("Lignes produits_touches :", len(table_produits))
print("Failles avec au moins un produit :", table_produits["cve_id"].nunique(), "sur", len(fiches))
print("vendor vides :", table_produits["vendor"].isna().sum())
print("product vides :", table_produits["product"].isna().sum())
print("Doublons exacts :", table_produits.duplicated().sum())
print(table_produits["vendor"].value_counts().head(10))


# -- Quelles clés trouve-t-on dans chaque produit (pour repérer des cas particuliers)
cles = Counter()
for f in fiches:
    for bloc in f["cve"].get("affected", []):
        for produit in bloc.get("affectedData", []):
            cles[tuple(sorted(produit.keys()))] += 1
for ensemble, nombre in cles.most_common():
    print(nombre, ensemble)


# -- Regard sur faiblesses
print("Lignes faiblesses :", len(table_faiblesses))
print("Failles avec au moins une faiblesse :", table_faiblesses["cve_id"].nunique(), "sur", len(fiches))
print("Doublons exacts :", table_faiblesses.duplicated().sum())
print(table_faiblesses["cwe"].value_counts().head(10))