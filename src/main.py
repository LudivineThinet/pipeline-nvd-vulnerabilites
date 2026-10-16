# ______________________________________________________________
# PIPELINE NVD : collecte, transformation, contrôles, chargement dans BigQuery
# Lancement complet. py src/main.py
# Lancement d'essai sans BigQuery. py src/main.py --debut 2026-10-14 --fin 2026-10-15 --sans-chargement
# ______________________________________________________________

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import collecte
import transformation


# Lit les options de la ligne de commande.
def lire_arguments():
    parseur = argparse.ArgumentParser(description="Pipeline des failles de sécurité du NVD")
    parseur.add_argument("--debut", default=collecte.DATE_DEBUT_DEFAUT.strftime("%Y-%m-%d"),
                         help="Premier jour à télécharger (AAAA-MM-JJ)")
    parseur.add_argument("--fin", default=None,
                         help="Dernier instant à télécharger (AAAA-MM-JJ). Par défaut maintenant")
    parseur.add_argument("--sans-chargement", action="store_true",
                         help="Ne pas charger dans BigQuery et écrire des CSV à la place")
    parseur.add_argument("--dossier-sortie", default="data/sortie",
                         help="Dossier des CSV quand on n'envoie pas à BigQuery")
    return parseur.parse_args()


def main():
    arguments = lire_arguments()
    debut_chrono = time.perf_counter()

    debut = datetime.strptime(arguments.debut, "%Y-%m-%d")
    if arguments.fin:
        fin = datetime.strptime(arguments.fin, "%Y-%m-%d")
    else:
        fin = datetime.now(timezone.utc).replace(tzinfo=None)
    # On vérifie la connexion à BigQuery avant les 17 minutes de téléchargement.
    if not arguments.sans_chargement:
        import chargement_bigquery
        chargement_bigquery.creer_client()
        print("Connexion à BigQuery vérifiée.")

    print(f"Période : du {debut:%Y-%m-%d} au {fin:%Y-%m-%d %H:%M} (UTC)")

    # 1. Collecte et transformation, faille après faille.
    bilan = {}
    lignes_vulnerabilites, lignes_produits, lignes_faiblesses = [], [], []
    rejetees = 0
    for fiche in collecte.iterer_failles(debut, fin, bilan):
        resultat = transformation.transformer_fiche(fiche)
        if resultat is None:
            rejetees += 1
            continue
        ligne, produits, faiblesses = resultat
        lignes_vulnerabilites.append(ligne)
        lignes_produits.extend(produits)
        lignes_faiblesses.extend(faiblesses)
    bilan["rejetees"] = rejetees

    # 2. Construction des tableaux et de la table des noms de types de défaut.
    tables = transformation.construire_tables(lignes_vulnerabilites, lignes_produits, lignes_faiblesses)
    catalogue, url_catalogue = collecte.telecharger_catalogue_cwe()
    print(f"Catalogue CWE téléchargé : {url_catalogue}")
    codes_utilises = set(tables["faiblesses"]["code_cwe"])
    tables["cwe_noms"] = transformation.construire_cwe_noms(catalogue, codes_utilises)

    # 3. Contrôles qualité. En cas d'erreur on s'arrête avant de toucher à BigQuery.
    erreurs, avertissements, rapport = transformation.controler_tables(tables, bilan)
    print("\nCONTRÔLES QUALITÉ")
    for ligne in rapport:
        print(" ", ligne)
    for avertissement in avertissements:
        print("  AVERTISSEMENT :", avertissement)
    for erreur in erreurs:
        print("  ERREUR :", erreur)
    if erreurs:
        print("Arrêt. Rien n'a été chargé.")
        sys.exit(1)

    # 4. Chargement dans BigQuery ou écriture de CSV pour un essai.
    print("\nCHARGEMENT")
    if arguments.sans_chargement:
        dossier = Path(arguments.dossier_sortie)
        dossier.mkdir(parents=True, exist_ok=True)
        for nom, tableau in tables.items():
            tableau.to_csv(dossier / f"{nom}.csv", index=False, encoding="utf-8")
        print(f"  CSV écrits dans {dossier}")
    else:
        chargement_bigquery.charger_tables(tables)

    print(f"\nTerminé en {round(time.perf_counter() - debut_chrono)} secondes.")


if __name__ == "__main__":
    main()