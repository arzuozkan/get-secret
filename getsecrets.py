import argparse
import re
import subprocess
import json
#import spacy
#import requests

def is_json(data):
    try:
        json.loads(data)
        return True
    except ValueError:
        return False

def print_matches(matches):
    if matches:
        for match in matches:
            print(match.group().strip())
        print("********************************")
    else:
        print("Seems nothin there.")

def extract_secrets(content):
    #basic usage fp fazla
    #regex_pattern=r'(password|key|token|secret|credential|key)(.+)'

    #password token api_key gibi verileri en az fp seviyesinde tespit edebilir.
    regex_pattern=r".*(password|key|token|secret|credential|admin|version)(?:(?!\n).){0,20}(=|:|\"| = | : )\s*([^\n|^\<|-]+).*"
    matches = re.finditer(regex_pattern, content, re.MULTILINE | re.IGNORECASE)
    print("Found sensitive data:\n")
    print_matches(matches)

def extract_secrets_in_json(content):
    json_data=json.loads(content)
    pattern = r'.*(password|token|key|api|client|kerberos|amazon|session|cookie).*'

    print("Found sensitives:\n")
    for key in json_data.keys():
        if re.search(pattern,key):
            print(key,":",json_data[key])

#relative paths detection
def find_relative_paths(content):
    regex=r'(href|src)="([^"]+\.(css|js|ico|svg)?[^\"]*)'
    matches = re.finditer(regex, content, re.MULTILINE | re.IGNORECASE)
    print_matches(matches)

#email, phone number detection
def find_personalInformation(content):
    phone_pattern=r'\b(?:\d{3}-\d{3}-\d{4}|\(\d{3}\) \d{3}-\d{4})\b'
    email_pattern=r'[\w\.]+@([\w-]+\.)+[\w-]{2,4}'
    matches = re.finditer(phone_pattern, content, re.MULTILINE | re.IGNORECASE)
    print_matches(matches)
    matches = re.finditer(email_pattern, content, re.MULTILINE | re.IGNORECASE)
    print_matches(matches)

def main():
    parser=argparse.ArgumentParser(description="Give an input file or string")

    parser.add_argument("-l","--localFile",type=str,help="Give a web content as a local file")
    parser.add_argument("-r","--remoteFile",type=str,help="Give a website page a URL")
    parser.add_argument("-s","--string",type=str,help="Give a string to extract info")
    parser.add_argument("--noextra",action="store_true",help="Disable relative path and personal information searching")
    args=parser.parse_args()
    web_content=None
    extras=True

    if args.noextra:
        print(args.noextra)
        extras=False

    if args.localFile:
        file_name=args.localFile
        try:
            with open(file_name,"r") as f:
                web_content="".join(f.readlines())
        except FileNotFoundError as e:
            print(e)
            return
        
    if args.remoteFile:
        print("Fetching the web content...")
        remote_site=args.remoteFile
        #basic curl command
        curl_command=["curl","-k",remote_site]

        response=subprocess.run(curl_command,capture_output=True,text=True)

        if "Just a moment..." in response.stdout:
            print("Required bypass WAF")
            curl_bypass= ['curl','-k',remote_site,
                          '-H','"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"',
                          '-H','"Accept-Encoding: gzip, deflate"',
                          '-H','"Accept-Language: en-US,en;q=0.9"',
                          '-H','"Upgrade-Insecure-Requests": "1"',
                          '-H','"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"',
                          '-H',''
                          ]

            return
        else:
            print("Exit Code:","OK" if not response.returncode else "NOT OK")
            web_content=response.stdout
        
    if args.string:
        print("Searching inside the given string..")
        web_content=args.string

    if web_content is not None:
        if is_json(web_content):
            print("Data is json format.")
            extract_secrets_in_json(web_content)
        else:
            extract_secrets(web_content)
            if extras:
                print("Finding relative paths\n")
                find_relative_paths(web_content)
                print("Searching any personal information\n")
                find_personalInformation(web_content)

        return 
    
    else:
        print("One argument required. More information -h")




if __name__=="__main__":
    # response = requests.get(url)

    # print("Status Code:", response.status_code)
    # print("Response Content:", response.text)
        
    #web_content=response.stdout

    # web_content = """
    # <meta name="description" content="WSTG - Stable on the main website for The OWASP Foundation. OWASP is a nonprofit foundation that works to improve the security of software.">
    # <!-- Use the DB administrator password for testing:  f@keP@a$$w0rD -->
    # <script type="application/json">
    # {"GOOGLE_MAP_API_KEY":"AIzaSyDUEBnKgwiqMNpDplT6ozE4Z0XxuAbqDi4", 
    # "RECAPTCHA_KEY":"6LcPscEUiAAAAHOwwM3fGvIx9rsPYUq62uRhGjJ0"}
    # </script>
    # """

    main()

