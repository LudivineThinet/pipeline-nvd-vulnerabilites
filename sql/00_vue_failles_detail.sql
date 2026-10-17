-- ______________________________________________________________
-- Vue de travail pour le dashboard Looker Studio
-- Une ligne par faille, produit et type de défaut.
-- Elle joint les 4 tables pour que tous les filtres marchent sur toutes les pages.
--
-- Pour compter sans doublon.
--   Nombre de failles   = SUM(premiere_ligne)
--   Score moyen         = AVG(score_faille)
--   Types de défaut     = COUNT_DISTINCT(code_cwe_precis)
--   Produits concernés  = COUNT_DISTINCT(produit_complet)
-- ______________________________________________________________

CREATE OR REPLACE VIEW `pipeline-nvd-vulnerabilites.nvd.v_failles_detail` AS
SELECT
  v.identifiant_cve,
  v.date_publication,
  v.date_modification,
  v.statut,
  v.score,
  v.gravite,
  v.origine_attaque,
  v.difficulte_attaque,
  v.compte_necessaire,
  v.action_victime,
  v.impact_confidentialite,
  v.impact_integrite,
  v.impact_disponibilite,
  v.type_note,
  p.editeur,
  p.produit,
  IF(p.editeur = 'non renseigné' OR p.produit = 'non renseigné',
     NULL,
     CONCAT(p.editeur, ' | ', p.produit)) AS produit_complet,
  f.code_cwe,
  IF(f.code_cwe = 'non précisé', NULL, f.code_cwe) AS code_cwe_precis,
  n.nom_cwe,
  -- Vaut 1 sur une seule ligne par faille. Sert à compter les failles sans doublon.
  IF(ROW_NUMBER() OVER (
       PARTITION BY v.identifiant_cve
       ORDER BY p.editeur, p.produit, f.code_cwe) = 1, 1, 0) AS premiere_ligne,
  -- Score de la faille sur sa première ligne seulement. Sert à faire une moyenne juste.
  IF(ROW_NUMBER() OVER (
       PARTITION BY v.identifiant_cve
       ORDER BY p.editeur, p.produit, f.code_cwe) = 1, v.score, NULL) AS score_faille
FROM `pipeline-nvd-vulnerabilites.nvd.vulnerabilites` AS v
LEFT JOIN `pipeline-nvd-vulnerabilites.nvd.produits_touches` AS p
  ON v.identifiant_cve = p.identifiant_cve
LEFT JOIN `pipeline-nvd-vulnerabilites.nvd.faiblesses` AS f
  ON v.identifiant_cve = f.identifiant_cve
LEFT JOIN `pipeline-nvd-vulnerabilites.nvd.cwe_noms` AS n
  ON f.code_cwe = n.code_cwe;