# ______________________________________________________________
# COLLECTE DES DONNÉES
# API du NVD (failles de sécurité) et catalogue CWE de MITRE (noms des types de défaut)
# ______________________________________________________________

import io
import time
import requests
import pandas as pd
from datetime import datetime, timedelta, timezone

URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# On essaie les adresses dans l'ordre jusqu'à en trouver une qui répond.
URLS_CATALOGUE_CWE = [
    "https://cwe.mitre.org/data/csv/2000.csv.zip",
    "https://cwe.mitre.org/data/csv/1000.csv.zip",
]

DATE_DEBUT_DEFAUT = datetime(2025, 10, 1)
JOURS_PAR_TRANCHE = 100   # l'API accepte 120 jours maximum par requête
TAILLE_PAGE = 2000        # maximum de failles par page
PAUSE_ENTRE_APPELS = 6    # en secondes


# ______________________________________________________________
# APPEL DE L'API AVEC GESTION DES ERREURS
# ______________________________________________________________

# Appelle l'API et réessaie après une attente si le serveur a un souci.
def appeler_api(params, max_essais=4, attente_base=6):
    for essai in range(1, max_essais + 1):
        try:
            reponse = requests.get(URL_NVD, params=params, timeout=30)
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
# DÉCOUPAGE DE LA PÉRIODE EN TRANCHES
# ______________________________________________________________

# Met une date au format attendu par l'API (millisecondes sur 3 chiffres).
def formater_date(date):
    return date.strftime("%Y-%m-%dT%H:%M:%S.") + f"{date.microsecond // 1000:03d}"


# Découpe la période en tranches de 100 jours maximum.
def decouper_periode(debut, fin, jours_max=JOURS_PAR_TRANCHE):
    tranches = []
    courant = debut
    while courant < fin:
        suivant = min(courant + timedelta(days=jours_max), fin)
        tranches.append((courant, suivant))
        courant = suivant
    return tranches


# ______________________________________________________________
# TÉLÉCHARGEMENT DES FAILLES
# ______________________________________________________________

# Renvoie les failles une par une, tranche après tranche et page après page.
# Le dictionnaire bilan reçoit le nombre de failles annoncées par l'API et le nombre reçu.
def iterer_failles(debut, fin, bilan):
    bilan["annoncees"] = 0
    bilan["recues"] = 0
    for numero, (debut_tranche, fin_tranche) in enumerate(decouper_periode(debut, fin), start=1):
        # La fin d'une tranche est une milliseconde avant le début de la suivante.
        fin_inclusive = fin_tranche - timedelta(milliseconds=1) if fin_tranche != fin else fin_tranche
        params_base = {
            "pubStartDate": formater_date(debut_tranche),
            "pubEndDate": formater_date(fin_inclusive),
        }
        print(f"Tranche {numero} : {params_base['pubStartDate']} -> {params_base['pubEndDate']}")

        index_debut = 0
        while True:
            page = appeler_api({**params_base, "resultsPerPage": TAILLE_PAGE, "startIndex": index_debut})
            total = page["totalResults"]
            for fiche in page["vulnerabilities"]:
                bilan["recues"] += 1
                yield fiche
            print(f"  A partir de {index_debut} : {min(index_debut + TAILLE_PAGE, total)}/{total} failles")
            index_debut += TAILLE_PAGE
            if index_debut >= total:
                break
            time.sleep(PAUSE_ENTRE_APPELS)

        bilan["annoncees"] += total
        time.sleep(PAUSE_ENTRE_APPELS)


# ______________________________________________________________
# TÉLÉCHARGEMENT DU CATALOGUE CWE
# ______________________________________________________________

# Télécharge le catalogue CWE de MITRE et le renvoie en tableau avec l'adresse utilisée.
def telecharger_catalogue_cwe():
    erreurs = []
    for url in URLS_CATALOGUE_CWE:
        for encodage in ("utf-8", "latin-1"):
            try:
                reponse = requests.get(url, timeout=60)
                reponse.raise_for_status()
                tableau = pd.read_csv(io.BytesIO(reponse.content), compression="zip",
                                      index_col=False, encoding=encodage)
                return tableau, url
            except Exception as erreur:
                erreurs.append(f"{url} ({encodage}) : {erreur}")
    raise RuntimeError("Catalogue CWE introuvable. " + " | ".join(erreurs))


# ______________________________________________________________
# TEST RAPIDE (py src/collecte.py)
# On télécharge une seule journée de failles et le début du catalogue CWE.
# ______________________________________________________________

if __name__ == "__main__":
    fin_test = datetime(2026, 10, 15)
    debut_test = fin_test - timedelta(days=1)
    bilan_test = {}
    fiches = list(iterer_failles(debut_test, fin_test, bilan_test))
    print("Failles reçues :", len(fiches), "sur", bilan_test["annoncees"], "annoncées")

    catalogue, url_utilisee = telecharger_catalogue_cwe()
    print("Catalogue CWE :", url_utilisee)
    print("Forme du tableau :", catalogue.shape)
    print("Colonnes :", catalogue.columns.tolist()[:6])
    print(catalogue.iloc[:3, :2])