# SCRIPT V1 : tests de l'API NVD

import time
import requests
import pandas as pd

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"



# ÉTAPE 2 : appel de l'API avec gestion des erreurs


# Appelle l'API et réessaie après une attente si le serveur a un problème.
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
# TESTS DES ÉTAPES 1 ET 2 (VALIDÉS, EN COMMENTAIRE)
# ______________________________________________________________

# -- Test 1 : un appel normal qui doit marcher du premier coup
# params_ok = {
#     "pubStartDate": "2026-10-14T00:00:00.000",
#     "pubEndDate": "2026-10-14T23:59:59.999",
#     "resultsPerPage": 1,
# }
# donnees = appeler_api(params_ok)
# print("Total de failles :", donnees["totalResults"])


# -- Test 2 : une mauvaise requête exprès (date de début sans date de fin)
# params_mauvais = {
#     "pubStartDate": "2026-10-14T00:00:00.000",
#     "resultsPerPage": 1,
# }
# try:
#     appeler_api(params_mauvais)
# except Exception as erreur:
#     print(type(erreur).__name__, "->", erreur)


# -- Test 3 : on regarde les en-têtes de la réponse 404 pour trouver le message d'erreur
# reponse = requests.get(URL, params=params_mauvais, timeout=30)
# print("Code :", reponse.status_code)
# for nom, valeur in reponse.headers.items():
#     print(nom, "->", valeur)


# ______________________________________________________________
# ÉTAPE 3 : structure d'une fiche (VALIDÉE)
# La fonction reste active, l'appel est en commentaire.
# ______________________________________________________________

# Affiche l'arborescence d'une fiche (clés, types et début des valeurs).
def decrire_structure(element, niveau=0, nom="racine"):
    marge = "  " * niveau
    if isinstance(element, dict):
        print(f"{marge}{nom} (dict, {len(element)} clés)")
        for cle, valeur in element.items():
            decrire_structure(valeur, niveau + 1, cle)
    elif isinstance(element, list):
        print(f"{marge}{nom} (liste, {len(element)} éléments)")
        if element:
            decrire_structure(element[0], niveau + 1, "[0]")
    else:
        apercu = str(element)[:50]
        print(f"{marge}{nom} = {apercu}")


# -- Appel : une seule faille du 14 octobre pour voir sa structure
# params_fiche = {
#     "pubStartDate": "2026-10-14T00:00:00.000",
#     "pubEndDate": "2026-10-14T23:59:59.999",
#     "resultsPerPage": 1,
# }
# donnees = appeler_api(params_fiche)
# fiche = donnees["vulnerabilities"][0]
# decrire_structure(fiche)


# ______________________________________________________________
# ÉTAPE 4 : extraction des colonnes, table vulnerabilites (ACTIF)
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


# -- Transforme une fiche en une ligne pour la table vulnerabilites
def extraire_vulnerabilite(fiche):
    cve = fiche["cve"]
    metrics = cve.get("metrics", {})
    ligne = {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
    }
    for suffixe, cle_metrique, champs in [
        ("v31", "cvssMetricV31", CHAMPS_V31),
        ("v40", "cvssMetricV40", CHAMPS_V40),
    ]:
        note = choisir_note(metrics.get(cle_metrique))
        donnees_cvss = note["cvssData"] if note else {}
        for colonne, champ_api in champs.items():
            ligne[colonne] = donnees_cvss.get(champ_api)
        ligne[f"type_note_{suffixe}"] = note.get("type") if note else None
    return ligne


# -- Récupère toutes les failles du 14 octobre en un seul appel
params_jour = {
    "pubStartDate": "2026-10-14T00:00:00.000",
    "pubEndDate": "2026-10-14T23:59:59.999",
    "resultsPerPage": 2000,
}
debut = time.perf_counter()
donnees = appeler_api(params_jour)
duree = time.perf_counter() - debut

fiches = donnees["vulnerabilities"]
print("Failles attendues :", donnees["totalResults"])
print("Failles reçues :", len(fiches))
print("Durée (secondes) :", round(duree, 2))


# -- Construit la table (une ligne par faille) et regarde les 3 premières
table_vuln = pd.DataFrame([extraire_vulnerabilite(f) for f in fiches])
print("Forme du tableau (lignes, colonnes) :", table_vuln.shape)
print("cve_id uniques :", table_vuln["cve_id"].is_unique)
#print(table_vuln.head(3).T)


# # -- Compte les valeurs vides et les valeurs distinctes de chaque colonne
# resume = pd.DataFrame({
#     "vides": table_vuln.isna().sum(),
#     "distinctes": table_vuln.nunique(),
# })
# print(resume)

# # Pour les colonnes avec peu de valeurs différentes, on affiche lesquelles.
# for colonne in table_vuln.columns:
#     if table_vuln[colonne].nunique() <= 8:
#         print(colonne, "->", sorted(table_vuln[colonne].dropna().unique().tolist()))

# ______________________________________________________________
# ÉTAPE 5 : comptage des notes v3.1 et v4.0 (ACTIF)
# ______________________________________________________________

# # -- Failles avec une note v3.1, une note v4.0, les deux ou aucune
# a_v31 = table_vuln["base_score_v31"].notna()
# a_v40 = table_vuln["base_score_v40"].notna()
# presence = pd.crosstab(a_v31, a_v40, rownames=["note v3.1"], colnames=["note v4.0"], margins=True)
# print(presence)


# # -- Part de notes Primary et Secondary pour chaque version
# print(table_vuln["type_note_v31"].value_counts(dropna=False))
# print(table_vuln["type_note_v40"].value_counts(dropna=False))


# # -- Failles par statut, et lien entre le statut et la présence d'une note v3.1
# print(table_vuln["vuln_status"].value_counts())
# print(pd.crosstab(table_vuln["vuln_status"], a_v31, colnames=["note v3.1"]))

# ______________________________________________________________
# ÉTAPE 6a : pagination (ACTIF)
# ______________________________________________________________

# -- Récupère toutes les pages d'une requête en avançant avec startIndex
def recuperer_toutes_les_pages(params, taille_page=300, pause=6):
    toutes = []
    index_debut = 0
    while True:
        page = appeler_api({**params, "resultsPerPage": taille_page, "startIndex": index_debut})
        total = page["totalResults"]
        toutes.extend(page["vulnerabilities"])
        print(f"A partir de {index_debut} : {len(page['vulnerabilities'])} reçues, {len(toutes)}/{total}")
        index_debut += taille_page
        if index_debut >= total:
            break
        time.sleep(pause)
    return toutes


# # -- Test sur la journée du 14 octobre avec des pages de 300
# params_pagination = {
#     "pubStartDate": "2026-10-14T00:00:00.000",
#     "pubEndDate": "2026-10-14T23:59:59.999",
# }
# fiches_pages = recuperer_toutes_les_pages(params_pagination, taille_page=300)
# ids_pages = [f["cve"]["id"] for f in fiches_pages]
# print("Failles reçues :", len(ids_pages))
# print("Failles distinctes :", len(set(ids_pages)))
# print("Mêmes failles que l'appel en une page :", set(ids_pages) == set(table_vuln["cve_id"]))

# ______________________________________________________________
# ÉTAPE 6b : failles modifiées depuis la veille (ACTIF)
# ______________________________________________________________

from datetime import datetime, timedelta, timezone

# -- Fenêtre de 24 heures qui finit maintenant (heure UTC)
format_date = "%Y-%m-%dT%H:%M:%S.000"
maintenant = datetime.now(timezone.utc).replace(tzinfo=None)
hier = maintenant - timedelta(days=1)
params_modif = {
    "lastModStartDate": hier.strftime(format_date),
    "lastModEndDate": maintenant.strftime(format_date),
}
print("Fenêtre :", params_modif["lastModStartDate"], "->", params_modif["lastModEndDate"])


# -- On compte d'abord sans rien télécharger (une seule faille demandée)
comptage = appeler_api({**params_modif, "resultsPerPage": 1})
print("Failles modifiées sur 24 h :", comptage["totalResults"])


# -- On récupère tout avec des pages de 2000
fiches_modif = recuperer_toutes_les_pages(params_modif, taille_page=2000)
table_modif = pd.DataFrame([extraire_vulnerabilite(f) for f in fiches_modif])
print("Failles reçues :", len(table_modif))
print("Failles distinctes :", table_modif["cve_id"].nunique())
print("Plus ancienne modification :", table_modif["last_modified"].min())
print("Plus récente modification :", table_modif["last_modified"].max())