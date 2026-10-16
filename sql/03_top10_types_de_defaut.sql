-- ______________________________________________________________
-- Question 3. Pourquoi ces failles existent ?
-- Les 10 types de défaut (CWE) les plus fréquents, avec leur nom.
-- On compte des failles distinctes. Les failles sans type précis sont exclues.
-- ______________________________________________________________

SELECT
  f.code_cwe,
  n.nom_cwe,
  COUNT(DISTINCT f.identifiant_cve) AS nb_failles
FROM `pipeline-nvd-vulnerabilites.nvd.faiblesses` AS f
JOIN `pipeline-nvd-vulnerabilites.nvd.cwe_noms` AS n
  ON f.code_cwe = n.code_cwe
WHERE f.code_cwe <> 'non précisé'
GROUP BY f.code_cwe, n.nom_cwe
ORDER BY nb_failles DESC
LIMIT 10;