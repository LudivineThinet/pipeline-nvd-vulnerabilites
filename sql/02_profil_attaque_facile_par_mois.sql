-- ______________________________________________________________
-- Question 2. Comment on nous attaque ?
-- Part des failles exploitables à distance, sans compte et sans action
-- de la victime. C'est le profil le plus dangereux.
-- ______________________________________________________________

SELECT
  DATE_TRUNC(DATE(date_publication), MONTH) AS mois,
  COUNT(*) AS nb_failles,
  COUNTIF(
    origine_attaque = 'NETWORK'
    AND compte_necessaire = 'NONE'
    AND action_victime = 'NONE'
  ) AS nb_profil_facile,
  ROUND(100 * COUNTIF(
    origine_attaque = 'NETWORK'
    AND compte_necessaire = 'NONE'
    AND action_victime = 'NONE'
  ) / COUNT(*), 1) AS part_profil_facile_pct
FROM `pipeline-nvd-vulnerabilites.nvd.vulnerabilites`
WHERE score IS NOT NULL
GROUP BY mois
ORDER BY mois;