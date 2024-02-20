import os
import sys
sys.path.append("..")

import subprocess

import pandas as pd

from Utils import FrontingUtils

config = FrontingUtils.get_config()

# Assign the input file name to a variable
input_file = config['FILE_PATHS']['cdn_domain_mapping_file_path']

# Check if the input file exists
if not os.path.isfile(input_file):
    print(f"Input file '{input_file}' not found.")
    sys.exit(1)

for option in config['DIR_PATHS']:
    dir_path = config['DIR_PATHS'][option]
    os.makedirs(dir_path, exist_ok=True)


df_cdn_domains = pd.read_csv(input_file, header = 0)
df_cdn_domains = df_cdn_domains[['cdn','domain_sld']].drop_duplicates()

for _,row in df_cdn_domains.iterrows():
    try:
        cdn = row["cdn"]
        domain = row["domain"]
        print(f"Crawling {domain} fron CDN :: {cdn}")
        os.makedirs(f"{config['DIR_PATHS']['crawling_results_path']}{cdn}_{domain}", exist_ok=True)
        subprocess.run(["node", "crawler.js", domain, cdn, config['DIR_PATHS']['crawling_results_path']])
    except:
        continue

FrontingUtils.filter_urls(config['FILE_PATHS']['cdn_domain_mapping_file_path'], config['FILE_PATHS']['domain_url_mapping_file_path'])