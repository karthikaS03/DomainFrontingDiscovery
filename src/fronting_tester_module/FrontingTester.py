import os
import re
import sys
sys.path.append("..")
import ssl
import json
import time
import socket
import argparse
import datetime

import pandas as pd
import concurrent.futures as cf

from itertools import chain
from collections import defaultdict

from Utils import FrontingUtils
from FrontingTest import FrontingTest

config = FrontingUtils.get_config()

class FrontingTester:

    def __init__(self):

        self.CONTENT_TYPES = {'text/javascript', 'video/webm', 'application/x-font-ttf', 'application/json', 'application/font-woff', 
                              'audio/mpeg','application/font-woff2', 'image/x-icon', 'application/font-sfnt', 'text/css', 'image/webp', 'font/otf', 'font/x-woff', 'application/x-font-woff2', 'text/json', 'text/xml', 'image/avif', 'application/rss+xml', 'application/octet-stream', 'font/woff', 'application/octet-stream', 'image/png', 'application/x-font-otf', 'video/mp4', 'text/plain', 'application/xml', 'application/javascript', 'application/x-javascript', 'image/jpg', 'image/svg+xml', 'application/x-font-woff', 'font/ttf', 'image/jpeg', 'image/gif', 'font/woff2', 'binary/octet-stream'
                              }

        
        self.test_obj = FrontingTest()
        self.ip_dets = defaultdict(list)
        self.shared_certificate_hosts = set()
        self.host_name_certificates = defaultdict(dict)
        self.result_path =  config['DIR_PATHS']['download_resources_path'] 

        self.df_urls = self.load_urls()
        self.df_cdn_domains = self.load_cdn_mappings()
        
        
    def load_cdn_mappings(self):
        try:
            return pd.read_csv(config['FILE_PATHS']['cdn_domain_mapping_file_path']) 
        except:
            return None

    def load_urls(self):
        try:
            df_tmp = pd.read_json(config['FILE_PATHS']['domain_url_mapping_file_path'], orient='records')
            df_tmp['content_type_final'] = df_tmp['content_type'].apply(lambda x: x.split(';')[0].rstrip(' '))
            df_tmp = df_tmp[df_tmp['content_type_final'].isin(self.CONTENT_TYPES)]
            return df_tmp
        except :
            return pd.DataFrame()

    
    def is_owned_by_same_organisation(self,target_domain, front_domain):
        
        self.get_certificate_details(target_domain)
        self.get_certificate_details(front_domain)

        target_dom_certificate = self.host_name_certificates[target_domain]
        front_dom_certificate = self.host_name_certificates[front_domain]
        res = False

        if frozenset([target_domain, front_domain]) in self.shared_certificate_hosts:
            print("Shared certificate", target_domain, front_domain)
            return True

        for name in target_dom_certificate.get("SAN",[]) + [target_dom_certificate.get("CN","")]:
            if '*.' in name:
                if re.match(name.replace(".","\.").replace("*",".*")+'$', front_domain):
                    res = True
                    break
            elif name == front_domain:
                res = True
                break
            
        for name in front_dom_certificate.get("SAN",[]) + [front_dom_certificate.get("CN","")]:
            if '*.' in name:
                if re.match(name.replace(".","\.").replace("*",".*")+'$', target_domain):
                    res = True
                    break
            elif name == target_domain:
                res = True
                break

        if res:
            self.shared_certificate_hosts.add(frozenset([target_domain, front_domain]))

        return False


    def get_certificate_details(self, hostname):

        if hostname in self.host_name_certificates:
            return
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                san = [entry[1] for entry in cert.get('subjectAltName', ()) if entry[0] == 'DNS']
                subject_terms = [s for sub in  cert['subject'] for s in  list(chain.from_iterable(sub))]
                common_name = subject_terms[subject_terms.index('commonName')+1]

                if common_name:
                    self.host_name_certificates[hostname] = {
                        "CN":  common_name,
                        "SAN": san
                    }


    def validate_test(self, dom1, dom2):

        return (FrontingUtils.get_SLD(dom1)!= FrontingUtils.get_SLD(dom2)) and (not self.is_owned_by_same_organisation(dom1,dom2))
                                    

    def validate_test_results(self):
            
            df_tests = pd.read_json(config['FILE_PATHS']['test_details_file_path'], orient='records')

            if df_tests.empty:
                print("No test cases were found to validate")
                return
            
            ### Restructures the dataframe so that it is easy to compare the digests between different types of request
            df_reg_case = df_tests[(df_tests['test_type']=='AHAD')].copy(deep=True)
            df_reg_case.rename(columns = {'output_digest': 'original_digest'}, inplace=True) 

            df_fhfd_case = df_tests[(df_tests['test_type']=='FHFD') ].copy(deep=True)
            df_fhfd_case.rename(columns = {'output_digest': 'fhfd_digest'}, inplace=True)
            
            df_front_cases = df_tests[(df_tests['test_type']=='AHFD') ]
            df_front_cases = df_front_cases.merge(df_reg_case[['test_id','original_digest']], how="left",left_on="test_id",right_on="test_id")
            df_front_cases = df_front_cases.merge(df_fhfd_case[['test_id','fhfd_digest']], how="left",left_on="test_id",right_on="test_id")
            
            ### Checks if the downloaded content during fronting request matches with the original content and 
            ### if the fronting domain itself doesn't host the same content 
            df_success = df_front_cases[(df_front_cases['test_result']=="Success") & 
                                        (df_front_cases['output_digest']==df_front_cases['original_digest']) & 
                                        (df_front_cases['output_digest']!=df_front_cases['fhfd_digest']) &
                                        (df_front_cases['attack_host']!=df_front_cases['front_domain'])
                                        ]
            
            ### Checks if the request for fronting wasn't redirected to the original target URL based on the Host parameter
            df_success = df_success[df_success.apply(lambda x : x['front_domain'] in x['attack_url'], axis=1)]
            
            ### Writes the successful cases of domain fronting requests to a file 
            if not df_success.empty:
                print('\n=====Domain Fronting Success!!=========')
                print(f"*check {config['FILE_PATHS']['fronting_success_cases_file_path']} for more details")
                df_success.to_json(config['FILE_PATHS']['fronting_success_cases_file_path'], orient="records",indent=2)
            else:
                print("No Success cases yet!!")

    def test_single(self, target_domain, front_domain, target_url):
        if self.validate_test(target_domain, front_domain):
            dst_path = os.path.join(self.result_path, FrontingUtils.get_SLD(target_domain).replace(".","-")+"_"+ str(datetime.datetime.now().timestamp()))
            os.makedirs(dst_path, exist_ok=True)
            test_results = self.test_obj.run_fronting_tests(target_domain, target_url, front_domain, dst_path)
            with open(config['FILE_PATHS']['test_details_file_path'],'w') as ff:
                json.dump(test_results, ff, indent = 2) 
        else:
            print("Invalid Test Case. The target and front domaisn were found to be related!!")

    def test_batch(self,):

            cdn_dets = defaultdict(dict)
            
            df_groups = self.df_urls.groupby(by=['cdn'])
            group_counts = df_groups[['original_domain']].nunique().reset_index().sort_values(by=['original_domain'])
            
            all_test_results = []
            for key in group_counts['cdn'].tolist():
                
                group = df_groups.get_group(key)
                
                for domain, dom_group in group.groupby(by=['original_domain']):
                    cdn_dets[key].update({domain: dom_group['resource_url'].unique().tolist()})
                    self.ip_dets[domain].extend(dom_group['server_ip'].unique().tolist())
            
            self.test_obj.ip_dets = self.ip_dets
            
            for cdn, domain_dets in cdn_dets.items():
                # print(cdn, domain_dets)
                cdn = cdn.split(".")[0]
                futures={}
                with cf.ThreadPoolExecutor(max_workers=20) as executor:
                    try:
                        ## Check if there's atleast two domains per CDN
                        if len(domain_dets)>1:
                            max_dom_count = int(config['PARAMS']['max_domain_count_per_cdn'])
                            domains = sorted(domain_dets, key = lambda k : len(set(domain_dets[k])), reverse = True)[:max_dom_count]

                            ### Note that any domain linked with the same CDN can be used as front domain even if an associated URL was not found. This is useful in case only few number of target domains were found. 
                            front_domains = list(set(domains + self.df_cdn_domains[self.df_cdn_domains["cdn"]==cdn]["full_domain"].unique().tolist()))[:max_dom_count]
                            print(time.ctime(), f'Testing {cdn} :: {len(domains)} attack domains and {len(front_domains)} front domains in total!!')
                            
                            for i,dom1 in enumerate(domains):  
                                dom1_tmp = dom1                  
                                count = 0
                                for j, dom2 in enumerate(front_domains):

                                    ## Test if the domains are not subdomains of each other and is not owned by the same organization
                                    is_test_valid = self.validate_test(dom1,dom2) 

                                    if is_test_valid: 
                                        
                                        urls = list(set(domain_dets.get(dom1_tmp,[])))[:2]
                                        # print(urls)
                                        print(f'Testing {len(urls)} URLs under domain :: {dom1_tmp} front_domain {dom2}')
                                        
                                        for attack_url in urls:
                                            # print("Performing Test for {} , {}, {} ".format(dom1,attack_url,dom2))
                                            url_domain = attack_url.split('/')[2]
                                            if dom1 != url_domain:
                                                dom2 = url_domain.replace(dom1,dom2)
                                                dom1 = url_domain
                                            
                                            if not os.path.exists(os.path.join(self.result_path,cdn+'_'+dom1+'_'+str(count))):
                                                os.mkdir(os.path.join(self.result_path,cdn+'_'+dom1+'_'+str(count)))
                                            
                                            futures[executor.submit(self.test_obj.run_fronting_tests, dom1, attack_url, dom2, os.path.join(self.result_path,cdn+'_'+dom1+'_'+str(count)))] = (dom1,attack_url,dom2)
                                            count += 1
                                try:
                                    for future in cf.as_completed(futures, timeout=300):
                                        dom1,url,dom2 = futures.pop(future)
                                        try:
                                            test_results = future.result()
                                            # print(test_results)
                                            all_test_results = all_test_results + test_results
                                            with open(config['FILE_PATHS']['test_details_file_path'],'w') as ff:
                                                json.dump(all_test_results, ff, indent = 2) 
                                        except Exception as er:
                                            print(sys._getframe(  ).f_code.co_name, (dom1,url,dom2),er)
                                except Exception as te:
                                    print(sys._getframe(  ).f_code.co_name, len(futures), te)
                                    pass
                    except Exception as ex:
                        print(ex)

            with open(config['FILE_PATHS']['test_details_file_path'],'w') as ff:
                json.dump(all_test_results, ff, indent = 2) 



def main():
    parser = argparse.ArgumentParser(description="Fronting Tester Componenet that can be used for testing a single case or a batch")
    parser.add_argument("mode", choices=["batch", "single"], help="Mode of operation: 'batch' or 'single'")
    parser.add_argument("-target_domain", "-t", type=str, help="Hidden Domain that is the true endpoint (required for single mode)")
    parser.add_argument("-front_domain","-f", type=str, help="Visible Domain that acts as Front (required for single mode)")
    parser.add_argument("-target_url","-u", type=str, help="URL belonging to target domain (required for single mode)")

    args = parser.parse_args()

    tester = FrontingTester()

    for option in config['DIR_PATHS']:
        dir_path = config['DIR_PATHS'][option]            
        os.makedirs(dir_path, exist_ok=True)
    print(args)
    if args.mode == 'batch':
        tester.test_batch()
    elif args.mode == 'single':
        if not all([args.target_domain, args.front_domain, args.target_url]):
            parser.error("For single mode, all of the parameters target_domain, fronting_domain and target_url are required.")
        tester.test_single(args.target_domain, args.front_domain, args.target_url)
    else:
        print("Invalid mode!!")
        exit()

    tester.validate_test_results()


if __name__ == "__main__":
    main()