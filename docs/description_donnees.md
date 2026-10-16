# Description des données

## Source

Les données viennent de l'API NVD CVE 2.0 du NIST (https://nvd.nist.gov/developers/vulnerabilities). Chaque fiche décrit une faille de sécurité identifiée par un code CVE. Le pipeline récupère toutes les failles publiées depuis le 1er octobre 2025 et les recharge en entier à chaque exécution.

Les noms des types de défaut viennent du catalogue CWE de The MITRE Corporation (https://cwe.mitre.org). CWE est une marque de The MITRE Corporation. Le catalogue est utilisé selon les CWE Terms of Use.

## Volumes au 16 octobre 2026

| Élément | Nombre |
|---|---|
| Failles reçues de l'API | 96 863 |
| Failles rejetées retirées | 2 460 |
| Failles gardées (table `vulnerabilites`) | 94 403 |
| Lignes de `produits_touches` | 195 178 |
| Lignes de `faiblesses` | 109 458 |
| Lignes de `cwe_noms` | 995 |

Ces chiffres bougent à chaque exécution car le NVD publie et modifie des failles tous les jours.

## Les 4 tables

Les tables sont dans le dataset `nvd` du projet BigQuery `pipeline-nvd-vulnerabilites`.

### `vulnerabilites`

Une ligne par faille. La clé est `identifiant_cve`.

| Colonne | Type | Contenu |
|---|---|---|
| `identifiant_cve` | texte | Identifiant de la faille (exemple CVE-2026-92817) |
| `date_publication` | date et heure | Date de publication par le NVD (UTC) |
| `date_modification` | date et heure | Dernière modification (UTC) |
| `statut` | texte | Statut dans le NVD (Analyzed, Deferred, Received...) |
| `score` | nombre | Score CVSS 3.1 de 0 à 10. Vide si la faille n'a pas de note |
| `gravite` | texte | LOW, MEDIUM, HIGH, CRITICAL (ou NONE). Vide si pas de note |
| `origine_attaque` | texte | NETWORK, ADJACENT_NETWORK, LOCAL ou PHYSICAL |
| `difficulte_attaque` | texte | LOW ou HIGH |
| `compte_necessaire` | texte | NONE, LOW ou HIGH |
| `action_victime` | texte | NONE ou REQUIRED |
| `impact_confidentialite` | texte | NONE, LOW ou HIGH |
| `impact_integrite` | texte | NONE, LOW ou HIGH |
| `impact_disponibilite` | texte | NONE, LOW ou HIGH |
| `type_note` | texte | Primary (note du NVD) ou Secondary (autre organisme) |

### `produits_touches`

Une ligne par faille et par produit. Il n'y a pas de doublon sur (faille, éditeur, produit).

| Colonne | Type | Contenu |
|---|---|---|
| `identifiant_cve` | texte | Lien vers `vulnerabilites` |
| `editeur` | texte | Éditeur en minuscules ou « non renseigné » |
| `editeur_origine` | texte | Éditeur tel qu'écrit par le NVD. Vide si l'API n'en donne pas |
| `produit` | texte | Nom du produit ou « non renseigné » |

### `faiblesses`

Une ligne par faille et par type de défaut.

| Colonne | Type | Contenu |
|---|---|---|
| `identifiant_cve` | texte | Lien vers `vulnerabilites` |
| `code_cwe` | texte | Type de défaut (exemple CWE-79) ou « non précisé » |

### `cwe_noms`

Le dictionnaire des types de défaut. La clé est `code_cwe`.

| Colonne | Type | Contenu |
|---|---|---|
| `code_cwe` | texte | Code CWE ou « non précisé » |
| `nom_cwe` | texte | Nom officiel donné par MITRE |

### Liens entre les tables

- `vulnerabilites.identifiant_cve` avec `produits_touches.identifiant_cve`
- `vulnerabilites.identifiant_cve` avec `faiblesses.identifiant_cve`
- `faiblesses.code_cwe` avec `cwe_noms.code_cwe`

Une faille peut toucher plusieurs produits et avoir plusieurs types de défaut. Pour compter des failles il faut donc utiliser `COUNT(DISTINCT identifiant_cve)`.

## Règles de nettoyage

Ces règles ont été décidées dans le notebook d'exploration (`notebooks/exploration_api.ipynb`) et sont appliquées par `src/transformation.py`.

| Sujet | Règle |
|---|---|
| Version de la note | Seule la note CVSS 3.1 est gardée |
| Choix de la note | La note Primary (donnée par le NVD) si elle existe. Sinon la première note Secondary |
| Failles rejetées | Retirées avant le chargement. Elles n'ont ni produit ni note ni type de défaut |
| Failles sans note | Gardées. Elles comptent dans les volumes mais pas dans les graphiques de gravité |
| Texte | Les codes HTML (exemple `&amp;`) sont décodés et les espaces inutiles retirés |
| Éditeurs | Passés en minuscules pour regrouper les variantes d'écriture. L'écriture d'origine est gardée dans `editeur_origine` |
| Éditeurs manquants | `n/a`, `Unknown` et valeur vide deviennent « non renseigné » |
| Produits en double | Une seule ligne par (faille, éditeur, produit) |
| Types de défaut vagues | `NVD-CWE-noinfo` et `NVD-CWE-Other` sont retirés quand la faille a un vrai type. Sinon la faille reçoit « non précisé » |
| Noms de colonnes | En français |

## Limites connues

- Environ 10 % des failles n'ont pas de note CVSS 3.1. Beaucoup sont récentes et attendent encore l'analyse du NVD. D'autres ont le statut Deferred. Le NVD ne les traite pas en priorité.
- Environ 8 % des failles n'ont pas de type de défaut précis.
- 25 codes CWE utilisés par les failles n'existent pas dans le catalogue MITRE. Leur nom est « Nom non trouvé dans le catalogue ».
- Les tables sont dans le bac à sable gratuit de BigQuery. Elles expirent au bout de 60 jours et il est impossible de modifier une ligne. Le pipeline supprime et recrée donc les tables entières à chaque exécution, ce qui remet aussi le compteur de 60 jours à zéro.