# Petit test d'écriture dans BigQuery avec le compte de service.
import pandas as pd
from dotenv import load_dotenv
from google.cloud import bigquery

# Je charge le fichier .env pour que GOOGLE_APPLICATION_CREDENTIALS soit défini.
load_dotenv()

PROJET = "pipeline-nvd-vulnerabilites"
TABLE = f"{PROJET}.nvd.test_ecriture"

# Le client lit la clé grâce à la variable d'environnement GOOGLE_APPLICATION_CREDENTIALS.
client = bigquery.Client(project=PROJET, location="EU")

# Je charge un tout petit tableau de 3 lignes en remplaçant la table si elle existe.
df_test = pd.DataFrame({"id": [1, 2, 3], "texte": ["a", "b", "c"]})
config = bigquery.LoadJobConfig(write_disposition="WRITE_TRUNCATE")
job = client.load_table_from_dataframe(df_test, TABLE, job_config=config)
job.result()

# Je relis les infos de la table pour vérifier l'écriture.
table = client.get_table(TABLE)
print("Lignes écrites :", table.num_rows)
print("Expiration de la table :", table.expires)