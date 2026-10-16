-- ______________________________________________________________
-- Question 4. Qui est touché ?
-- Les 10 éditeurs avec le plus de failles et leur score moyen.
-- Une faille touche souvent plusieurs produits d'un même éditeur.
-- On déduplique d'abord (éditeur, faille) pour ne pas la compter plusieurs fois.
-- ______________________________________________________________

WITH paires AS (
  SELECT DISTINCT editeur, identifiant_cve
  FROM `pipeline-nvd-vulnerabilites.nvd.produits_touches`
  WHERE editeur <> 'non renseigné'
)
SELECT
  p.editeur,
  COUNT(*) AS nb_failles,
  ROUND(AVG(v.score), 2) AS score_moyen
FROM paires AS p
JOIN `pipeline-nvd-vulnerabilites.nvd.vulnerabilites` AS v
  ON p.identifiant_cve = v.identifiant_cve
GROUP BY p.editeur
ORDER BY nb_failles DESC
LIMIT 10;