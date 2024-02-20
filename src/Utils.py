import os
import json
import tldextract
import configparser
import pandas as pd


class FrontingUtils:

    @staticmethod
    def get_SLD(domain):
            try:
                extract = tldextract.TLDExtract()
                ext = extract(domain)
                return ext.registered_domain
            except Exception as e:
                return domain
    
    @staticmethod
    def get_config():
        config = configparser.ConfigParser()
        config.read( os.path.dirname(os.path.abspath(__file__))+'/config.ini')
        return config

    @staticmethod
    def get_full_domain(url):
        try:
            extract = tldextract.TLDExtract()
            ext = extract(url)
            return '.'.join(part for part in ext if part)
        except Exception as e:
            print(e)
            return None

    @staticmethod
    def filter_urls(cdn_domain_file, domain_urls_file):
        resources = []

        df_cdn_domains = pd.read_csv(cdn_domain_file, header=0)
        crawler_results_path = FrontingUtils.get_config()['FILE_PATHS']['crawling_results_path']
        for dir in os.listdir(crawler_results_path):
            headers = {}
            try:
                visited_domain = dir.split('_')[1]
                related_domains = df_cdn_domains[df_cdn_domains['domain_sld']==visited_domain]['full_domain'].unique().tolist()
                file = os.path.join(crawler_results_path, dir,visited_domain+'_headers.json')
                with open(file,'r') as f:
                    headers = json.load(f)
                res_count = 0
                for rec in headers['table']:
                    url_dom = FrontingUtils.get_full_domain(rec['response_url'])
                 
                    ### Fitler URLs to only retaint hose that share the same domain that's of interest
                    if url_dom in related_domains :
                        res_det = {'cdn': dir.split('_')[0],
                                        'visited_domain': visited_domain,
                                        'original_domain': url_dom,
                                        'resource_url': rec['response_url'],
                                        'content_type': rec['header']['content-type'],
                                        'server_ip': rec['server_info']['ip']
                                }
                
                        resources.append(res_det)
                        res_count += 1
                
            except Exception as e:
                print(e)
                continue
        
        with open(domain_urls_file,'w') as f:
            json.dump(resources, f, indent=2)
        