import os
import sys
sys.path.append("..")
import pandas as pd
import concurrent.futures as cf

from Utils import FrontingUtils
from FrontingTest import FrontingTest

config = FrontingUtils.get_config()


def validate_tests():
        
        ## TODO: Add certificate verification 
        
        df_tests = pd.read_json(config['FILE_PATHS']['test_details_file_path'], orient='records')

        ### Restructures the dataframe so that it is easy to compare the digests between different types of request
        df_reg_case = df_tests[(df_tests['test_type']=='AHAD') ]
        df_reg_case['original_digest'] = df_reg_case['output_digest']

        df_fhfd_case = df_tests[(df_tests['test_type']=='FHFD') ]
        df_fhfd_case['fhfd_digest'] = df_fhfd_case['output_digest']
        
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
            df_success.to_json(config['FILE_PATHS']['fronting_success_cases_file_path'], orient="records",indent=2)
        else:
            print("No Success cases yet!!")


if __name__=="__main__": 

    for option in config['DIR_PATHS']:
        dir_path = config['DIR_PATHS'][option]            
        os.makedirs(dir_path, exist_ok=True)

    test = FrontingTest()
    test.start()
    validate_tests()