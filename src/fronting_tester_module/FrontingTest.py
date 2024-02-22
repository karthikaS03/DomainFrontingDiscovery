import os

import sys
sys.path.append("..")
import time
import json
import hashlib
import urllib3
import requests


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
        self.result_path =  config['DIR_PATHS']['download_resources_path'] 
        self.ip_dets = {}
        

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
                    print(response.headers['Location'])
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
                continue

        return test_results
