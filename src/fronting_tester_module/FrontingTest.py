import os
import re
import sys
sys.path.append("..")
import ssl
import time
import json
import socket
import hashlib
import urllib3
import requests
import configparser
import pandas as pd
import concurrent.futures as cf

from itertools import chain
from collections import defaultdict
from mimetypes import guess_extension
from http.client import HTTPConnection  
from requests.exceptions import SSLError

from Utils import FrontingUtils

config = FrontingUtils.get_config() 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FrontingTest:

    '''
    Brief explanation of test types
    AHAD: Check if the Url download works when setting host name the same as the target SNI
    AHFD: Check if domain fronting works when changing the SNI to front domain while the host is target domain
    FHFD: Check if the URL doesn't download the same resource when SNI and Host point to the fronting domain
    '''
    def __init__(self):

        self.TEST_TYPES = ['AHAD', 'AHFD', 'FHFD']
        self.CONTENT_TYPES = {'text/javascript', 'video/webm', 'application/x-font-ttf', 'application/json', 'application/font-woff', 
                              'audio/mpeg','application/font-woff2', 'image/x-icon', 'application/font-sfnt', 'text/css', 'image/webp', 'font/otf', 'font/x-woff', 'application/x-font-woff2', 'text/json', 'text/xml', 'image/avif', 'application/rss+xml', 'application/octet-stream', 'font/woff', 'application/octet-stream', 'image/png', 'application/x-font-otf', 'video/mp4', 'text/plain', 'application/xml', 'application/javascript', 'application/x-javascript', 'image/jpg', 'image/svg+xml', 'application/x-font-woff', 'font/ttf', 'image/jpeg', 'image/gif', 'font/woff2', 'binary/octet-stream'
                              }
        self.ip_dets = defaultdict(list)
        self.result_path =  config['DIR_PATHS']['download_resources_path'] 
        self.df_cdn_domains = pd.read_csv(config['FILE_PATHS']['cdn_domain_mapping_file_path']) 
        self.df_urls = pd.DataFrame()
        self.host_name_certificates = defaultdict(dict)
        self.shared_certificate_hosts = set()
        self.load_urls(config['FILE_PATHS']['domain_url_mapping_file_path'])
        
    def load_urls(self,json_file):
        df_tmp = pd.read_json(json_file, orient='records')
        df_tmp['content_type_final'] = df_tmp['content_type'].apply(lambda x: x.split(';')[0].rstrip(' '))
        df_tmp = df_tmp[df_tmp['content_type_final'].isin(self.CONTENT_TYPES)]
        self.df_urls = df_tmp
   

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
            print('Adding Shared Certificate ', target_domain, front_domain, res)
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
        

    def request_resource(self, attack_host, attack_url, front_domain, res_path, verify=True):
        headers = {}
        original_url = attack_url
        response_headers = []

        if attack_host:
            headers = {'Host': attack_host,
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)'}
            attack_url = attack_url.replace(attack_host, front_domain)
        
        response = None
        try:
            retry = 0
            while retry <=20:
                response = requests.get(attack_url, headers=headers,
                                        timeout=60, allow_redirects=False, verify=verify)
                response_headers.append(json.dumps(dict(response.headers)))
                
                if 'Location' in response.headers:
                    attack_url = response.headers['Location']
                    if attack_url==original_url:
                        break
                else:
                    break
                retry += 1
            
            if response.status_code == 200:
                ## Store response based on the resource type
                ext = guess_extension(response.headers['content-type'].partition(';')[0].strip())
                
                ext = ext if ext!=None else ""
                res_name = res_path.split('/')[-1]
                file_path = res_path+ext
                res_content = response.content
                if type(res_content) is str:
                    txt_type = 'w'
                else:
                    txt_type = 'wb'

                with open(file_path,txt_type) as f:
                    f.write(res_content)

                ### Calculate signature of the file for later comparisons
                hasher = hashlib.sha1()
                with open(file_path, 'rb') as afile:
                    buf = afile.read()    
                    hasher.update(buf)
                digest = hasher.hexdigest()
 
                os.rename(file_path, file_path.replace(res_name, res_name+'_'+digest))
                return (response.url, response_headers, digest, 'Request Success!!')
            else: 
                raise Exception((response.status_code, attack_host))
        except SSLError as se:
                return (attack_url, response_headers, None, "SSL_Error")
        except Exception as ex:
            message_partial = f'000 - {attack_host} - FAIL'
            
            if type(ex) == requests.exceptions.ConnectTimeout:
                message_partial = f'XXX - {attack_host} - Connection Timeout'
            # Catch an exception when requests cannot make a connection.
            elif type(ex) == requests.exceptions.ConnectionError:
                message_partial = f'XXX - {attack_host} - No connection'
            # Catch an exception when the response was made but the return code != 200.
            elif type(ex.args[0]) == tuple:
                status_code, domain = ex.args[0]
                message_partial = f'{status_code} - {domain}'
            # Catch an exception when the requests library encounters an error and return gracefully.
            elif 'response' in ex:
                message_partial = f'{ex.response.status_code} - {attack_host}'
            else:
                message_partial = str(ex)
            return (response.url if response else '', response_headers, None, message_partial)
    

    def run_fronting_tests(self, attack_host, attack_url, front_domain, result_path):
        test_results = []
        test_id = result_path.split('/')[-1]
        for test_type in self.TEST_TYPES:
            try:
                time.sleep(1)  
                if test_type == 'AHAD':
                    attack_param = (attack_host, attack_url, attack_host, os.path.join(result_path,'AHAD_sample'),True)                    
                elif test_type == 'AHFD':
                    attack_param = (attack_host, attack_url, front_domain, os.path.join(result_path,'AHFD_sample'),True)                    
                elif test_type == 'FHFD':
                    attack_param = (front_domain, attack_url.replace(attack_host,front_domain), front_domain, os.path.join(result_path,'FHFD_sample'),True)                    
               
                url, headers, res, msg = self.request_resource(attack_param[0], attack_param[1], attack_param[2], attack_param[3],attack_param[4])

                test_results.append({   'test_id': test_id,
                                        'test_type':test_type, 
                                        'attack_host': attack_param[0],
                                        'attack_url': url,
                                        'front_domain': attack_param[2],
                                        'response_headers': headers,
                                        'output_res': msg,
                                        'output_digest': res,
                                        'test_result': 'Success' if (test_type in {'AHAD','AHFD'} and res) or (test_type in {'FHFD'} and not res) else 'Failed',
                                        'host_ip': self.ip_dets.get(attack_param[0],""),
                                        'front_domain_ip':self.ip_dets.get(attack_param[2],"")
                                    })
                
                ### If the resource cannot be downloaded from the target domain, then abort that test case
                if test_type == 'AHAD' and not res:
                    break 

            except Exception as eef:
                print(sys._getframe(  ).f_code.co_name, str(eef))
                # with open("errors.txt","a") as ff:
                #     ff.write(attack_host + ":: "+ eef +"\n")
                continue

        return test_results


    def start(self,):

        cdn_dets = defaultdict(dict)
        
        df_groups = self.df_urls.groupby(by=['cdn'])
        group_counts = df_groups[['original_domain']].nunique().reset_index().sort_values(by=['original_domain'])
        
        all_test_results = []
        for key in group_counts['cdn'].tolist():
            
            group = df_groups.get_group(key)
            
            for domain, dom_group in group.groupby(by=['original_domain']):
                print(domain)
                cdn_dets[key].update({domain: dom_group['resource_url'].unique().tolist()})
                self.ip_dets[domain].extend(dom_group['server_ip'].unique().tolist())
        
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
                                is_test_valid =  (FrontingUtils.get_SLD(dom1)!= FrontingUtils.get_SLD(dom2)) and (not self.is_owned_by_same_organisation(dom1,dom2))
                                
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
                                        
                                        futures[executor.submit(self.run_fronting_tests, dom1, attack_url, dom2, os.path.join(self.result_path,cdn+'_'+dom1+'_'+str(count)))] = (dom1,attack_url,dom2)
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
