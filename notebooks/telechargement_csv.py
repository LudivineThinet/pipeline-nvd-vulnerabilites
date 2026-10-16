# ______________________________________________________________
# TÉLÉCHARGEMENT DES FAILLES NVD EN UN SEUL CSV (pour l'exploration)
# ______________________________________________________________

import time
import requests
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta, timezone

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Le CSV est écrit dans le dossier data, à la racine du projet (un cran au-dessus de src).
CHEMIN_CSV = Path(__file__).resolve().parent.parent / "data" / "nvd_failles.csv"


# ______________________________________________________________
# APPEL DE L'API (copie de script_v1.py)
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
# DÉCOUPAGE DE LA PÉRIODE (l'API accepte 120 jours maximum par requête)
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


# ______________________________________________________________
# EXTRACTION : une ligne par faille
# ______________________________________________________________

# -- Choix de la note : Primary si elle existe, sinon la première de la liste
def choisir_note(liste_notes):
    if not liste_notes:
        return None
    for note in liste_notes:
        if note.get("type") == "Primary":
            return note
    return liste_notes[0]


# -- Nos noms de colonnes et les champs de l'API qui correspondent
CHAMPS_V31 = {
    "base_score_v31": "baseScore",
    "base_severity_v31": "baseSeverity",
    "attack_vector_v31": "attackVector",
    "attack_complexity_v31": "attackComplexity",
    "privileges_required_v31": "privilegesRequired",
    "user_interaction_v31": "userInteraction",
    "confidentiality_impact_v31": "confidentialityImpact",
    "integrity_impact_v31": "integrityImpact",
    "availability_impact_v31": "availabilityImpact",
}
CHAMPS_V40 = {
    "base_score_v40": "baseScore",
    "base_severity_v40": "baseSeverity",
    "attack_vector_v40": "attackVector",
    "attack_complexity_v40": "attackComplexity",
    "attack_requirements_v40": "attackRequirements",
    "privileges_required_v40": "privilegesRequired",
    "user_interaction_v40": "userInteraction",
    "confidentiality_impact_v40": "vulnConfidentialityImpact",
    "integrity_impact_v40": "vulnIntegrityImpact",
    "availability_impact_v40": "vulnAvailabilityImpact",
}


# -- Transforme une fiche en une ligne de CSV (25 colonnes + produits + cwes)
def extraire_ligne(fiche):
    cve = fiche["cve"]
    metrics = cve.get("metrics", {})
    ligne = {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
    }

    # Les notes v3.1 et v4.0
    for suffixe, cle_metrique, champs in [
        ("v31", "cvssMetricV31", CHAMPS_V31),
        ("v40", "cvssMetricV40", CHAMPS_V40),
    ]:
        note = choisir_note(metrics.get(cle_metrique))
        donnees_cvss = note["cvssData"] if note else {}
        for colonne, champ_api in champs.items():
            ligne[colonne] = donnees_cvss.get(champ_api)
        ligne[f"type_note_{suffixe}"] = note.get("type") if note else None

    # Les produits touchés, sous la forme "éditeur|produit" séparés par des ;
    produits = []
    for bloc in cve.get("affected", []):
        for produit in bloc.get("affectedData", []):
            produits.append(f"{produit.get('vendor') or ''}|{produit.get('product') or ''}")
    ligne["produits"] = ";".join(produits)

    # Les types de défaut (CWE) séparés par des ;
    cwes = []
    for faiblesse in cve.get("weaknesses", []):
        for description in faiblesse.get("description", []):
            cwes.append(description.get("value") or "")
    ligne["cwes"] = ";".join(cwes)

    return ligne


# ______________________________________________________________
# TÉLÉCHARGEMENT DE TOUTE LA PÉRIODE
# ______________________________________________________________

# -- Période du 1er octobre 2025 à maintenant (heure UTC)
debut_periode = datetime(2025, 10, 1)
fin_periode = datetime.now(timezone.utc).replace(tzinfo=None)
tranches = decouper_periode(debut_periode, fin_periode)
print("Nombre de tranches :", len(tranches))

debut_chrono = time.perf_counter()
lignes = []
total_annonce = 0


# -- Une tranche après l'autre et dans chaque tranche une page après l'autre
for numero, (debut, fin) in enumerate(tranches, start=1):
    fin_inclusive = fin - timedelta(milliseconds=1) if fin != fin_periode else fin
    params_base = {
        "pubStartDate": formater_date(debut),
        "pubEndDate": formater_date(fin_inclusive),
    }
    print(f"Tranche {numero} : {params_base['pubStartDate']} -> {params_base['pubEndDate']}")

    index_debut = 0
    while True:
        page = appeler_api({**params_base, "resultsPerPage": 2000, "startIndex": index_debut})
        total = page["totalResults"]
        for fiche in page["vulnerabilities"]:
            lignes.append(extraire_ligne(fiche))
        print(f"  A partir de {index_debut} : {len(lignes)} failles récupérées au total")
        index_debut += 2000
        if index_debut >= total:
            break
        time.sleep(6)

    total_annonce += total
    time.sleep(6)


# -- Écriture du CSV
CHEMIN_CSV.parent.mkdir(parents=True, exist_ok=True)
table = pd.DataFrame(lignes)
table.to_csv(CHEMIN_CSV, index=False)

print("Durée (secondes) :", round(time.perf_counter() - debut_chrono))
print("Failles annoncées par l'API :", total_annonce)
print("Lignes écrites :", len(table))
print("Failles distinctes :", table["cve_id"].nunique())
print("Colonnes :", table.shape[1])
print("Fichier :", CHEMIN_CSV)