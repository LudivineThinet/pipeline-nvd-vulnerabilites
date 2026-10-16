# ______________________________________________________________
# TRANSFORMATION DES DONNÉES
# Règles de nettoyage décidées dans le notebook d'exploration
# ______________________________________________________________

import html
import pandas as pd

VALEUR_MANQUANTE = "non renseigné"
NON_PRECISE = "non précisé"
CODES_CWE_VAGUES = {"NVD-CWE-Other", "NVD-CWE-noinfo"}
EDITEURS_MANQUANTS = {"", "n/a", "unknown"}   # comparés en minuscules
GRAVITES_ATTENDUES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
NOM_CWE_INCONNU = "Nom non trouvé dans le catalogue"

# Nom de colonne en français et champ de l'API (note v3.1) qui correspond.
CHAMPS_NOTE = {
    "score": "baseScore",
    "gravite": "baseSeverity",
    "origine_attaque": "attackVector",
    "difficulte_attaque": "attackComplexity",
    "compte_necessaire": "privilegesRequired",
    "action_victime": "userInteraction",
    "impact_confidentialite": "confidentialityImpact",
    "impact_integrite": "integrityImpact",
    "impact_disponibilite": "availabilityImpact",
}

COLONNES_VULNERABILITES = (
    ["identifiant_cve", "date_publication", "date_modification", "statut"]
    + list(CHAMPS_NOTE.keys())
    + ["type_note"]
)
COLONNES_PRODUITS = ["identifiant_cve", "editeur", "editeur_origine", "produit"]
COLONNES_FAIBLESSES = ["identifiant_cve", "code_cwe"]


# ______________________________________________________________
# OUTILS DE NETTOYAGE
# ______________________________________________________________

# Décode le code HTML (par exemple &amp;) et retire les espaces au début et à la fin.
def nettoyer_texte(valeur):
    if valeur is None:
        return ""
    return html.unescape(str(valeur)).strip()


# Choisit la note Primary si elle existe. Sinon la première de la liste.
def choisir_note(liste_notes):
    if not liste_notes:
        return None
    for note in liste_notes:
        if note.get("type") == "Primary":
            return note
    return liste_notes[0]


# ______________________________________________________________
# EXTRACTION D'UNE FAILLE
# ______________________________________________________________

# Une ligne par produit touché. Les doublons d'une même faille sont supprimés.
def extraire_produits(identifiant, cve):
    lignes = {}
    for bloc in cve.get("affected", []):
        for produit in bloc.get("affectedData", []):
            editeur_origine = nettoyer_texte(produit.get("vendor"))
            nom_produit = nettoyer_texte(produit.get("product"))

            # L'éditeur sert de clé en minuscules. Un éditeur manquant devient « non renseigné ».
            editeur = editeur_origine.lower()
            if editeur in EDITEURS_MANQUANTS:
                editeur = VALEUR_MANQUANTE
            if nom_produit == "":
                nom_produit = VALEUR_MANQUANTE

            cle = (editeur, nom_produit)
            if cle not in lignes:
                lignes[cle] = {
                    "identifiant_cve": identifiant,
                    "editeur": editeur,
                    "editeur_origine": editeur_origine or None,
                    "produit": nom_produit,
                }
    return list(lignes.values())


# Une ligne par type de défaut précis. Sans type précis la faille reçoit « non précisé ».
def extraire_faiblesses(identifiant, cve):
    codes = []
    for faiblesse in cve.get("weaknesses", []):
        for description in faiblesse.get("description", []):
            code = nettoyer_texte(description.get("value"))
            if code and code not in codes:
                codes.append(code)

    codes_precis = [code for code in codes if code not in CODES_CWE_VAGUES]
    if not codes_precis:
        codes_precis = [NON_PRECISE]
    return [{"identifiant_cve": identifiant, "code_cwe": code} for code in codes_precis]


# Transforme une fiche de l'API en trois groupes de lignes.
# Renvoie None pour une faille rejetée (elle est exclue de toutes les analyses).
def transformer_fiche(fiche):
    cve = fiche["cve"]
    if cve.get("vulnStatus") == "Rejected":
        return None

    identifiant = cve.get("id")
    note = choisir_note(cve.get("metrics", {}).get("cvssMetricV31"))
    donnees_cvss = note["cvssData"] if note else {}

    ligne = {
        "identifiant_cve": identifiant,
        "date_publication": cve.get("published"),
        "date_modification": cve.get("lastModified"),
        "statut": cve.get("vulnStatus"),
    }
    for colonne, champ_api in CHAMPS_NOTE.items():
        ligne[colonne] = donnees_cvss.get(champ_api)
    ligne["type_note"] = note.get("type") if note else None

    return ligne, extraire_produits(identifiant, cve), extraire_faiblesses(identifiant, cve)


# ______________________________________________________________
# CONSTRUCTION DES TABLEAUX
# ______________________________________________________________

# Construit les trois tableaux avec les bons types de colonnes.
def construire_tables(lignes_vulnerabilites, lignes_produits, lignes_faiblesses):
    vulnerabilites = pd.DataFrame(lignes_vulnerabilites, columns=COLONNES_VULNERABILITES)
    vulnerabilites["date_publication"] = pd.to_datetime(vulnerabilites["date_publication"])
    vulnerabilites["date_modification"] = pd.to_datetime(vulnerabilites["date_modification"])
    vulnerabilites["score"] = pd.to_numeric(vulnerabilites["score"])

    return {
        "vulnerabilites": vulnerabilites,
        "produits_touches": pd.DataFrame(lignes_produits, columns=COLONNES_PRODUITS),
        "faiblesses": pd.DataFrame(lignes_faiblesses, columns=COLONNES_FAIBLESSES),
    }


# Construit la table des noms de types de défaut à partir du catalogue CWE de MITRE.
# Les codes utilisés mais absents du catalogue reçoivent un nom indiquant qu'il est introuvable.
def construire_cwe_noms(catalogue, codes_utilises):
    colonne_id = "CWE-ID" if "CWE-ID" in catalogue.columns else catalogue.columns[0]
    colonne_nom = "Name" if "Name" in catalogue.columns else catalogue.columns[1]

    identifiants = catalogue[colonne_id].astype(str).str.strip().str.replace(r"\.0$", "", regex=True)
    codes = identifiants.where(identifiants.str.startswith("CWE-"), "CWE-" + identifiants)
    cwe_noms = pd.DataFrame({"code_cwe": codes, "nom_cwe": catalogue[colonne_nom].astype(str).str.strip()})
    cwe_noms = cwe_noms.drop_duplicates(subset="code_cwe")

    manquants = [c for c in sorted(codes_utilises) if c not in set(cwe_noms["code_cwe"]) and c != NON_PRECISE]
    lignes_ajoutees = [{"code_cwe": code, "nom_cwe": NOM_CWE_INCONNU} for code in manquants]
    lignes_ajoutees.append({"code_cwe": NON_PRECISE, "nom_cwe": "Non précisé"})
    cwe_noms = pd.concat([cwe_noms, pd.DataFrame(lignes_ajoutees)], ignore_index=True)
    return cwe_noms


# ______________________________________________________________
# CONTRÔLES QUALITÉ
# ______________________________________________________________

# Vérifie les tableaux avant le chargement. Renvoie les erreurs, les avertissements et le rapport.
def controler_tables(tables, bilan):
    vulnerabilites = tables["vulnerabilites"]
    produits = tables["produits_touches"]
    faiblesses = tables["faiblesses"]
    cwe_noms = tables["cwe_noms"]
    erreurs, avertissements, rapport = [], [], []

    # Failles reçues par rapport à ce que l'API annonce.
    annoncees, recues = bilan.get("annoncees", 0), bilan.get("recues", 0)
    rapport.append(f"Failles annoncées par l'API : {annoncees}. Failles reçues : {recues}.")
    if annoncees and recues < 0.99 * annoncees:
        erreurs.append(f"Trop peu de failles reçues ({recues} sur {annoncees}).")
    elif recues != annoncees:
        avertissements.append(f"Écart entre les failles reçues ({recues}) et annoncées ({annoncees}).")
    rapport.append(f"Failles rejetées retirées : {bilan.get('rejetees', 0)}.")

    # Table vulnerabilites.
    rapport.append(f"Table vulnerabilites : {len(vulnerabilites)} lignes.")
    if len(vulnerabilites) == 0:
        erreurs.append("La table vulnerabilites est vide.")
    if vulnerabilites["identifiant_cve"].isna().any():
        erreurs.append("Des identifiants de faille sont vides.")
    if not vulnerabilites["identifiant_cve"].is_unique:
        erreurs.append("Des identifiants de faille sont en double.")
    scores = vulnerabilites["score"].dropna()
    if ((scores < 0) | (scores > 10)).any():
        erreurs.append("Des scores sont en dehors de l'échelle de 0 à 10.")
    gravites_inconnues = set(vulnerabilites["gravite"].dropna().unique()) - GRAVITES_ATTENDUES
    if gravites_inconnues:
        avertissements.append(f"Gravités inattendues : {sorted(gravites_inconnues)}.")
    sans_note = int(vulnerabilites["score"].isna().sum())
    part = round(100 * sans_note / len(vulnerabilites), 1) if len(vulnerabilites) else 0
    rapport.append(f"Failles sans note v3.1 : {sans_note} ({part} %).")

    # Table produits_touches.
    rapport.append(f"Table produits_touches : {len(produits)} lignes.")
    if not produits["identifiant_cve"].isin(vulnerabilites["identifiant_cve"]).all():
        erreurs.append("Des produits sont liés à une faille absente de vulnerabilites.")
    if produits.duplicated(subset=["identifiant_cve", "editeur", "produit"]).any():
        erreurs.append("La table produits_touches contient des doublons.")
    sans_produit = len(set(vulnerabilites["identifiant_cve"]) - set(produits["identifiant_cve"]))
    if sans_produit:
        avertissements.append(f"{sans_produit} failles n'ont aucun produit.")
    rapport.append(f"Lignes avec un éditeur « {VALEUR_MANQUANTE} » : {int((produits['editeur'] == VALEUR_MANQUANTE).sum())}.")

    # Table faiblesses.
    rapport.append(f"Table faiblesses : {len(faiblesses)} lignes.")
    if not faiblesses["identifiant_cve"].isin(vulnerabilites["identifiant_cve"]).all():
        erreurs.append("Des faiblesses sont liées à une faille absente de vulnerabilites.")
    if faiblesses.duplicated().any():
        erreurs.append("La table faiblesses contient des doublons.")
    sans_faiblesse = len(set(vulnerabilites["identifiant_cve"]) - set(faiblesses["identifiant_cve"]))
    if sans_faiblesse:
        erreurs.append(f"{sans_faiblesse} failles n'ont aucune ligne dans faiblesses.")
    non_precises = int((faiblesses["code_cwe"] == NON_PRECISE).sum())
    rapport.append(f"Failles avec un type de défaut « {NON_PRECISE} » : {non_precises}.")

    # Table cwe_noms.
    inconnus = int((cwe_noms["nom_cwe"] == NOM_CWE_INCONNU).sum())
    rapport.append(f"Table cwe_noms : {len(cwe_noms)} lignes dont {inconnus} codes sans nom dans le catalogue.")
    if inconnus:
        avertissements.append(f"{inconnus} codes CWE utilisés sont absents du catalogue.")
    if not faiblesses["code_cwe"].isin(cwe_noms["code_cwe"]).all():
        erreurs.append("Des codes de faiblesses sont absents de cwe_noms.")

    return erreurs, avertissements, rapport