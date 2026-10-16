# Contrôles de qualité

Les contrôles sont faits par la fonction `controler_tables` de `src/transformation.py`. Ils s'exécutent après le nettoyage et avant tout chargement dans BigQuery.

Un contrôle peut produire une **erreur** ou un **avertissement**. Une erreur arrête le pipeline. Rien n'est alors chargé et les tables BigQuery existantes restent intactes. Un avertissement est écrit dans le rapport mais n'arrête rien.

## Erreurs qui arrêtent le pipeline

| Contrôle | Pourquoi |
|---|---|
| Moins de 99 % des failles annoncées par l'API ont été reçues | Le téléchargement est incomplet |
| La table `vulnerabilites` est vide | Aucune donnée à charger |
| Un identifiant de faille est vide | La clé de la table serait cassée |
| Un identifiant de faille apparaît deux fois | La clé doit être unique |
| Un score est hors de l'échelle de 0 à 10 | Le score CVSS ne peut pas sortir de cette échelle |
| Un produit est lié à une faille absente de `vulnerabilites` | Lien cassé entre les tables |
| `produits_touches` contient un doublon | Les produits seraient comptés deux fois |
| Un type de défaut est lié à une faille absente de `vulnerabilites` | Lien cassé entre les tables |
| `faiblesses` contient un doublon | Les types de défaut seraient comptés deux fois |
| Une faille n'a aucune ligne dans `faiblesses` | Elle doit au moins avoir « non précisé » |
| Un code de `faiblesses` est absent de `cwe_noms` | Le nom du type de défaut serait introuvable |

## Avertissements

| Contrôle | Pourquoi |
|---|---|
| Léger écart entre failles reçues et annoncées (moins de 1 %) | Des failles ont pu être publiées pendant le téléchargement |
| Valeur de gravité inattendue | Le NVD aurait introduit un nouveau niveau |
| Failles sans aucun produit | Normal pour des failles très récentes |
| Codes CWE absents du catalogue MITRE | Le nom sera « Nom non trouvé dans le catalogue » |

## Chiffres suivis dans le rapport

Le rapport affiche aussi ces chiffres à chaque exécution pour repérer une dérive.

- Nombre de failles rejetées retirées
- Part de failles sans note v3.1
- Nombre de lignes avec un éditeur « non renseigné »
- Nombre de failles avec un type de défaut « non précisé »
- Nombre de codes CWE sans nom dans le catalogue

## Contrôles pendant la collecte

- Chaque page de l'API est redemandée en cas d'erreur temporaire (délai dépassé, codes 403, 429 et 5xx), avec une attente de plus en plus longue.
- Une pause de 6 secondes est faite entre deux appels pour respecter les limites du NVD.
- Le nombre de failles reçues est comparé au nombre annoncé par l'API pour chaque période.

## Contrôles après le chargement

- Le nombre de lignes de chaque table dans BigQuery doit être égal au nombre de lignes envoyées.
- Le nombre de scores vides dans BigQuery doit être égal à celui du tableau envoyé.

## Exemple de rapport réel

Rapport de l'exécution complète du 16 octobre 2026.

```
CONTRÔLES QUALITÉ
  Failles annoncées par l'API : 96863. Failles reçues : 96863.
  Failles rejetées retirées : 2460.
  Table vulnerabilites : 94403 lignes.
  Failles sans note v3.1 : 9673 (10.2 %).
  Table produits_touches : 195178 lignes.
  Lignes avec un éditeur « non renseigné » : 7331.
  Table faiblesses : 109458 lignes.
  Failles avec un type de défaut « non précisé » : 7583.
  Table cwe_noms : 995 lignes dont 25 codes sans nom dans le catalogue.
  AVERTISSEMENT : 25 codes CWE utilisés sont absents du catalogue.
```

Aucune erreur n'a été relevée. L'avertissement sur les 25 codes CWE est connu et accepté.

## Contrôles faits dans le notebook d'exploration

Avant d'écrire le pipeline les données ont été explorées dans `notebooks/exploration_api.ipynb`. Cette étape a permis de décider des règles de nettoyage (voir `description_donnees.md`) et de repérer les valeurs manquantes et les doublons.