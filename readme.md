# DomainFronting Discovery Tool

This project includes the source code for the tool developed as part of the research paper "Discovering and Measuring CDNs Prone to Domain Fronting" ([Link](https://doi.org/10.1145/3589334.3645656)).

The tool is designed to test the possibility of Domain Fronting in Content Delivery Networks (CDNs) by crafting special requests involving existing customers of a particular CDN. Through this tool, you can assess the extent of Domain Fronting in the wild despite mitigation measures taken by popular CDN providers. Our study reveals that it is possible for adversaries to misuse Domain Fronting to hide malicious communications and emphasizes the need for additional mitigation measures that can defend against such misuse.

## Project Structure

The Source Code in the `src` folder is structured as follows:

### Configuration

Before using this tool, you need to specify information about the domains and the related CDNs in a CSV file with the following fields:
- `cdn`: denotes the CDN name
- `full_domain`: denotes the fully qualified domain name associated with a CDN according to the DNS records
- `domain_sld`: eTLD+1 of the full_domain field

This CSV file should be passed to the tool as the parameter `cdn_domain_mapping_file_path` using `config.ini`. To map the domains associated with CDNs, we leverage Passive and ([ActiveDNS](http://www.activednsproject.org/)) records in our research. While that code isn't made publicly available, we provide a list of CDN host names that we identified as associated to a CDN in the file "cdn_domain_mapper/cdn_domain_keywords.csv".

### Modules

1. **crawler_module:**
   This module includes the code for crawling the eTLD+1 domains associated with different CDNs. The crawler visits the given domains, captures all the URLs, including those of its own subdomains and third-party domains, that were requested, and stores additional information such as the contacted IP address, HTML content, and screenshot of the visited webpage. The results are stored in the data folder. Finally, after crawling all the given domains, the module filters those URLs linked to domains associated with the CDNs. The outcome after filtering is a JSON file that lists the different resources associated with different domains and CDNs in a file specified using the parameter `domain_url_mapping_file_path` in the config file.
   
   To execute the crawler, run the command 

   ```python
    # python crawl_urls.py
    ```

    Python file `crawl_urls.py`. This program requires as input (read from config file) the CDN_DOMAIN mapping CSV file that uses the columns `cdn` and `domain_sld` to be crawled.

2. **fronting_tester_module:**
   This module is responsible for crafting requests required to test domain fronting for a given set of domains for different CDNs. This file takes the filtered list of resources and starts by generating test tuples that contain the different information required for performing fronting tests. Finally, the results of "valid" test cases are stored in the JSON file specified using the parameter `test_details_file_path` in the config file. Additionally, further validation is performed to filter successful fronting test cases that verify if the fronting test case is accurate. These carefully checked results are finally written in a JSON file specified using the parameter `fronting_success_cases_file_path` in the config file. 

    To execute the tester, run the command 

    ```python
    # python FrontingTester.py
    ```

## Contact

For questions or feedback, you can reach us at:
- Email: [ksubramani@gatech.edu](mailto:ksubramani@gatech.edu)

## Citation

If you use this project in your research or find it helpful, please consider citing the paper:

@misc{paper_link,
title = {Discovering and Measuring CDNs Prone to Domain Fronting},
year = {2024},
howpublished = {\url{https://doi.org/10.1145/3589334.3645656}}
}