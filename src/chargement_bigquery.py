# ______________________________________________________________
# CHARGEMENT DANS BIGQUERY
# Le bac à sable n'autorise pas le DML. On envoie donc des tables entières.
# ______________________________________________________________

import os
from pathlib import Path
from dotenv import load_dotenv
from google.cloud import bigquery

# Je charge le fichier .env à la racine du repo (un dossier au-dessus de src/).
# Sur GitHub Actions il n'existe pas. La variable est alors déjà définie par le workflow.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

PROJET = os.getenv("PROJET_GCP", "pipeline-nvd-vulnerabilites")
DATASET = os.getenv("DATASET_BQ", "nvd")
LOCALISATION = "EU"

CHAMP = bigquery.SchemaField

SCHEMAS = {
    "vulnerabilites": [
        CHAMP("identifiant_cve", "STRING", description="Identifiant de la faille (CVE)"),
        CHAMP("date_publication", "TIMESTAMP", description="Date de publication de la faille (UTC)"),
        CHAMP("date_modification", "TIMESTAMP", description="Date de dernière modification (UTC)"),
        CHAMP("statut", "STRING", description="Statut de la faille dans le NVD"),
        CHAMP("score", "FLOAT", description="Score de gravité CVSS 3.1 de 0 à 10"),
        CHAMP("gravite", "STRING", description="Niveau de gravité CVSS 3.1"),
        CHAMP("origine_attaque", "STRING", description="D'où l'attaque peut venir (réseau, local...)"),
        CHAMP("difficulte_attaque", "STRING", description="Difficulté de l'attaque (LOW ou HIGH)"),
        CHAMP("compte_necessaire", "STRING", description="Niveau de compte nécessaire à l'attaquant"),
        CHAMP("action_victime", "STRING", description="Action requise de la victime (NONE ou REQUIRED)"),
        CHAMP("impact_confidentialite", "STRING", description="Impact sur la confidentialité"),
        CHAMP("impact_integrite", "STRING", description="Impact sur l'intégrité"),
        CHAMP("impact_disponibilite", "STRING", description="Impact sur la disponibilité"),
        CHAMP("type_note", "STRING", description="Primary (note du NVD) ou Secondary (autre organisation)"),
    ],
    "produits_touches": [
        CHAMP("identifiant_cve", "STRING", description="Identifiant de la faille (CVE)"),
        CHAMP("editeur", "STRING", description="Éditeur en minuscules ou « non renseigné »"),
        CHAMP("editeur_origine", "STRING", description="Éditeur tel qu'écrit dans l'API"),
        CHAMP("produit", "STRING", description="Produit touché ou « non renseigné »"),
    ],
    "faiblesses": [
        CHAMP("identifiant_cve", "STRING", description="Identifiant de la faille (CVE)"),
        CHAMP("code_cwe", "STRING", description="Code du type de défaut (CWE) ou « non précisé »"),
    ],
    "cwe_noms": [
        CHAMP("code_cwe", "STRING", description="Code du type de défaut (CWE) ou « non précisé »"),
        CHAMP("nom_cwe", "STRING", description="Nom du type de défaut (en anglais, source MITRE)"),
    ],
}

DESCRIPTIONS_TABLES = {
    "vulnerabilites": "Une ligne par faille publiée par le NVD (hors failles rejetées). Note CVSS 3.1 seulement.",
    "produits_touches": "Une ligne par faille et par produit touché, sans doublons.",
    "faiblesses": "Une ligne par faille et par type de défaut précis. « non précisé » si aucun type précis.",
    "cwe_noms": ("Noms des types de défaut. Source CWE de The MITRE Corporation (https://cwe.mitre.org). "
                 "CWE est une marque de The MITRE Corporation. Utilisé selon les CWE Terms of Use."),
}


# Crée le client BigQuery. La clé est lue grâce à GOOGLE_APPLICATION_CREDENTIALS.
def creer_client():
    chemin_cle = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if not chemin_cle:
        raise RuntimeError("GOOGLE_APPLICATION_CREDENTIALS n'est pas défini. Vérifier le fichier .env à la racine du repo.")
    if not Path(chemin_cle).is_file():
        raise RuntimeError(f"Le fichier de clé est introuvable : {chemin_cle}")
    return bigquery.Client(project=PROJET, location=LOCALISATION)


# Supprime la table puis la recrée avec le tableau. Une table neuve repart pour 60 jours.
def charger_table(client, nom, tableau):
    reference = f"{PROJET}.{DATASET}.{nom}"
    try:
        client.delete_table(reference, not_found_ok=True)
    except Exception as erreur:
        print(f"  Suppression impossible ({erreur}). La table sera remplacée à la place.")

    config = bigquery.LoadJobConfig(schema=SCHEMAS[nom], write_disposition="WRITE_TRUNCATE")
    client.load_table_from_dataframe(tableau, reference, job_config=config).result()

    table = client.get_table(reference)
    table.description = DESCRIPTIONS_TABLES[nom]
    client.update_table(table, ["description"])
    print(f"  {nom} : {table.num_rows} lignes chargées (expire le {table.expires:%d/%m/%Y}).")
    return table


# Charge les quatre tableaux et vérifie le nombre de lignes et les scores vides.
def charger_tables(tables):
    client = creer_client()
    for nom, tableau in tables.items():
        table = charger_table(client, nom, tableau)
        if table.num_rows != len(tableau):
            raise RuntimeError(f"{nom} : {table.num_rows} lignes dans BigQuery pour {len(tableau)} envoyées.")

    # Les scores vides doivent rester vides (NULL) dans BigQuery.
    requete = f"SELECT COUNTIF(score IS NULL) AS vides FROM `{PROJET}.{DATASET}.vulnerabilites`"
    vides_bq = list(client.query(requete).result())[0]["vides"]
    vides_pandas = int(tables["vulnerabilites"]["score"].isna().sum())
    print(f"  Scores vides. Envoyés : {vides_pandas}. Dans BigQuery : {vides_bq}.")
    if vides_bq != vides_pandas:
        raise RuntimeError("Les scores vides n'ont pas été chargés comme vides.")