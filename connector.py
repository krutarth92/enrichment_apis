
"""
Virustotal V3 API (Public API) to get report of diiferent types o IOCS: IP Address, URL, Domain and File

It is supported for Virustotal public API only. Not fully functioned for Premium API.

Get Virustotal API to use this module.

"""


import requests
import json

class Virustotalv3():
    
    def __init__(self, apikey, base_url, **kwargs) -> None:
        
        self.apikey = apikey
        self.base_url = base_url
        self.headers = {
            "accept": "application/json",
            "x-apikey": apikey
        }
    
    def request_manager(self, action_endpoint, request_type="GET",
                        params=None, payload=None,
                        **kwargs):
        
        try:
            endpoint_url = "{}/api/v3/{}".format(
                self.base_url,
                action_endpoint
                )
            headers = self.headers
            
            if request_type == "GET":
                api_req = requests.get(
                    endpoint_url,
                    headers=headers
                )
            
            if request_type == "POST":
                api_req = requests.post(
                    endpoint_url,
                    json=payload,
                    headers=headers
                )
                
            if request_type == "PUT":
                api_req = requests.get(
                    endpoint_url,
                    headers=headers
                )
            
            
            action_status_code = api_req.status_code

            if action_status_code >=200 and action_status_code <400:
                action_response = {
                    "action_response": api_req.json(),
                    "status_code": str(action_status_code),
                    "action_status": "SUCCESS"
                }                

            if action_status_code >= 400 and action_status_code < 500:
                action_response = {
                    "action_response": api_req.json(),
                    "status_code": str(action_status_code),
                    "action_status": "ERROR"
                }
            
            if action_status_code >=500:
                action_response = {
                    "action_response": api_req.json(),
                    "status_code": str(action_status_code),
                    "action_status": "ERROR"
                }

        except Exception:
            action_response = {
                "action_response": "Error! Something went wrong!",
                "status_code": str(action_status_code),
                "action_status": "Exception Ocurred! FAILED"
            }
        
        return action_response
    

    """
    Virustotal actions to get IOC reports:    
    """

    # Get IP Address Report
    def act_get_ipaddress_report(self, ip_address_to_check):

        """
        Variables:
        ip_address_to_check: URL identifier or base64 representation of URL to scan (w/o padding) :: MANDATORY
        """        
        
        ip_address_endpoint = "ip_addresses/{}".format(ip_address_to_check)
        get_req = self.request_manager(action_endpoint=ip_address_endpoint, request_type="GET")
        return get_req

    # Get Domain Report
    def act_get_domain_report(self, domain_to_check):
        
        """
        Variables:
        domain_to_check: Domain name :: MANDATORY
        """        
        domain_endpoint = "domains/{}".format(domain_to_check)
        get_req = self.request_manager(action_endpoint=domain_endpoint, request_type="GET")
        return get_req

    # Get URL Analysis Report
    def act_get_url_analysis_report(self, url_to_check):

        """
        Variables:
        url_to_check: URL identifier or base64 representation of URL to scan (w/o padding) :: MANDATORY
        """        
        
        url_endpoint = "urls/{}".format(url_to_check)
        get_req = self.request_manager(action_endpoint=url_endpoint, request_type="GET")
        return get_req

    # Get file Report from Hash value
    def act_get_file_report(self, file_hash_to_check):
        
        """
        Variables:
        file_hash_to_check: SHA-256, SHA-1 or MD5 identifying the file input required :: MANDATORY
        """
        
        url_endpoint = "files/{}".format(file_hash_to_check)
        get_req = self.request_manager(action_endpoint=url_endpoint, request_type="GET")
        return get_req

