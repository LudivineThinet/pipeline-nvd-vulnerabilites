-- ______________________________________________________________
-- Question 1. Où en est-on ?
-- Nombre de failles publiées par mois et par niveau de gravité.
-- Les failles sans note v3.1 n'ont pas de gravité, elles sont exclues ici.
-- ______________________________________________________________

SELECT
  DATE_TRUNC(DATE(date_publication), MONTH) AS mois,
  gravite,
  COUNT(*) AS nb_failles
FROM `pipeline-nvd-vulnerabilites.nvd.vulnerabilites`
WHERE gravite IS NOT NULL
GROUP BY mois, gravite
ORDER BY mois, gravite;