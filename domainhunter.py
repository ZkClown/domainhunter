#!/usr/bin/env python


import time 
import random
import argparse
import json
import base64
import os
import requests
from bs4 import BeautifulSoup
from texttable import Texttable

requests.packages.urllib3.disable_warnings()

## Functions

def doSleep(timing):
    if timing == 0:
        time.sleep(random.randrange(90,120))
    elif timing == 1:
        time.sleep(random.randrange(60,90))
    elif timing == 2:
        time.sleep(random.randrange(30,60))
    elif timing == 3:
        time.sleep(random.randrange(10,20))
    elif timing == 4:
        time.sleep(random.randrange(5,10))
    # There's no elif timing == 5 here because we don't want to sleep for -t 5

def checkBluecoat(domain, useragent, session):
    try:
        url = 'https://sitereview.bluecoat.com/resource/lookup'
        postData = {'url':domain,'captcha':''}
        headers = {'User-Agent':useragent,
                   'Accept':'application/json, text/plain, */*',
                   'Content-Type':'application/json; charset=UTF-8',
                   'Referer':'https://sitereview.bluecoat.com/lookup'}

        print('[*] BlueCoat: {}'.format(domain))
        response = session.post(url,headers=headers,json=postData,verify=False)
        responseJSON = json.loads(response.text)
        
        if 'errorType' in responseJSON:
            a = responseJSON['errorType']
        else:
            a = responseJSON['categorization'][0]['name']
        
        return a

    except Exception as e:
        print('[-] Error retrieving Bluecoat reputation! {0}'.format(e))
        return "error"

def checkIBMXForce(domain, useragent, session):
    try: 
        url = 'https://exchange.xforce.ibmcloud.com/url/{}'.format(domain)
        headers = {'User-Agent':useragent,
                    'Accept':'application/json, text/plain, */*',
                    'x-ui':'XFE',
                    'Origin':url,
                    'Referer':url}

        print('[*] IBM xForce: {}'.format(domain))

        url = 'https://api.xforce.ibmcloud.com/url/{}'.format(domain)
        response = session.get(url,headers=headers,verify=False)

        responseJSON = json.loads(response.text)

        if 'error' in responseJSON:
            a = responseJSON['error']

        elif not responseJSON['result']['cats']:
            a = 'Uncategorized'
	
	## TO-DO - Add noticed when "intrusion" category is returned. This is indication of rate limit / brute-force protection hit on the endpoint        

        else:
            categories = ''
            # Parse all dictionary keys and append to single string to get Category names
            for key in responseJSON["result"]['cats']:
                categories += '{0}, '.format(str(key))

            a = '{0}(Score: {1})'.format(categories,str(responseJSON['result']['score']))

        return a

    except Exception as e:
        print('[-] Error retrieving IBM-Xforce reputation! {0}'.format(e))
        return "error"

def downloadMalwareDomains(malwaredomainsURL, headers, session):
    url = malwaredomainsURL
    response = session.get(url=url,headers=headers,verify=False)
    responseText = response.text
    if response.status_code == 200:
        return responseText
    else:
        print("[-] Error reaching:{}  Status: {}").format(url, response.status_code)

def checkDomain(domain, maldomainsList, useragent, session):
    print('[*] Fetching domain reputation for: {}'.format(domain))

    if domain in maldomainsList:
        print("[!] {}: Identified as known malware domain (malwaredomains.com)".format(domain))
      
    bluecoat = checkBluecoat(domain,useragent, session)
    print("[+] {}: {}".format(domain, bluecoat))
    
    ibmxforce = checkIBMXForce(domain, useragent, session)
    print("[+] {}: {}".format(domain, ibmxforce))

    print("")
    
    results = [domain,bluecoat,ibmxforce]
    return results

def drawTable(header,data, maxwidth):
    
    data.insert(0,header)
    t = Texttable(max_width=maxwidth)
    t.add_rows(data)
    t.header(header)
    
    return(t.draw())

def parseListDomain(domains,maldomainsList, keyword=False):
    res = []
    soup = BeautifulSoup(domains, 'lxml')   
    try:
        table = soup.find("table")

        for row in table.findAll('tr')[1:]:
            cells = row.findAll("td")
            
            domain                  = row.find('td').find('a').text   # domain
            # fav                     = cells[1].find(text=True)   # fav
            # nbChar                  = cells[2].find(text=True)   # NB char
            # backlink                = cells[3].find(text=True)   # BackLink
            # backlinkFromDiffDomains = cells[4].find(text=True)   # Backlink from diff domains
            birth                   = cells[5].find(text=True)   # Birth
            # birth2                  = cells[6].find(text=True)   # Birth
            archiveDotOrg           = cells[7].find(text=True)   # Archive.org Crawl result
            # alexa                   = cells[8].find(text=True)   # Alexa
            # mmgr                    = cells[9].find(text=True)   # MMGR
            # dmoz                    = cells[10].find(text=True)   # DMOZ
            # TLDs                    = cells[11].find(text=True) # TLDs Reg
            dotCom                  = cells[12].find(text=True) # .com
            dotNet                  = cells[13].find(text=True) # .net
            dotOrg                  = cells[14].find(text=True) # .org
            dotBiz                  = cells[15].find(text=True) # .biz
            dotInfo                 = cells[16].find(text=True) # .info
            dotDe                   = cells[17].find(text=True) # .de
            # additionDate            = cells[18].find(text=True) # Add Date
            # rdt                     = cells[19].find(text=True) # RDT
            # wpl                     = cells[20].find(text=True) # WPL
            listF                   = cells[21].find(text=True) # List
            statusOrigin            = cells[22].find(text=True) # Status
            # links                   = cells[23].find(text=True) # Links 
            
            # create available TLD list
            available = ''
            if dotCom == "available":
                available += ".com "

            if dotNet == "available":
                available += ".net "

            if dotOrg == "available":
                available += ".org "

            if dotBiz == "available":
                available += ".biz "

            if dotInfo == "available":
                available += ".info "
            
            if dotDe == "available":
                available += ".de "
            
            # Only grab status for keyword searches since it doesn't exist otherwise
            status = ""
            if keyword:
                status = statusOrigin 
            
            # print(listF)
            # Only add Expired, not Pending, Backorder, etc
            if listF == "Expired" or statusOrigin.lower() == "available":
                if domain not in maldomainsList:
                    res.append((domain,birth,archiveDotOrg,available,status)) 
                else:
                    continue

    except Exception as e: 
        print("[!] Error: ", e)
        return None
    return res

def initParser():
    parser = argparse.ArgumentParser(description='Finds expired domains, domain categorization, and Archive.org history to determine good candidates for C2 and phishing domains')
    parser.add_argument('-a','--alexa', help='Filter results to Alexa listings', required=False, default=0, action='store_const', const=1)
    parser.add_argument('-o','--output', help='Output File', required=False)
    parser.add_argument('-l','--login', help='Login to connect to expireddomains.com', required=True)
    parser.add_argument('-p','--password', help='Password to connect to expireddomains.com', required=True)
    parser.add_argument('-k','--keyword', help='Keyword used to refine search results', required=False, default=False, type=str, dest='keyword')
    parser.add_argument('-c','--check', help='Perform domain reputation checks', required=False, default=False, action='store_true', dest='check')
    parser.add_argument('-f','--filename', help='Specify input file of line delimited domain names to check', required=False, default=False, type=str, dest='filename')
    parser.add_argument('-r','--maxresults', help='Number of results to return when querying latest expired/deleted domains', required=False, default=100, type=int, dest='maxresults')
    parser.add_argument('-s','--single', help='Performs detailed reputation checks against a single domain name/IP.', required=False, default=False, dest='single')
    parser.add_argument('-t','--timing', help='Modifies request timing to avoid CAPTCHAs. Slowest(0) = 90-120 seconds, Default(3) = 10-20 seconds, Fastest(5) = no delay', required=False, default=3, type=int, choices=range(0,6), dest='timing')
    parser.add_argument('-w','--maxwidth', help='Width of text table', required=False, default=400, type=int, dest='maxwidth')
    return parser.parse_args()


# Annoyingly when querying specific keywords the expireddomains.net site requires additional cookies which 
# are set in JavaScript and not recognized by Requests so we add them here manually.
# May not be needed, but the _pk_id.10.dd0a cookie only requires a single . to be successful
# In order to somewhat match a real cookie, but still be different, random integers are introduced
def genRandomCookie():
    r1 = random.randint(100000,999999)
    # Known good example _pk_id.10.dd0a cookie: 5abbbc772cbacfb1.1496760705.2.1496760705.1496760705
    pk_str = '5abbbc772cbacfb1' + '.1496' + str(r1) + '.2.1496' + str(r1) + '.1496' + str(r1)

    jar = requests.cookies.RequestsCookieJar()
    jar.set('_pk_ses.10.dd0a', '*', domain='member.expireddomains.net', path='/')
    jar.set('_pk_id.10.dd0a', pk_str, domain='member.expireddomains.net', path='/')
    return jar

def genOutputFile(outputName, sortedDomains):
    # Build HTML Table
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    html = ''
    htmlHeader = '<html><head><title>Expired Domain List</title></head>'
    htmlBody = '<body><p>The following available domains report was generated at {}</p>'.format(timestamp)
    htmlTableHeader = '''
                
                 <table border="1" align="center">
                    <th>Domain</th>
                    <th>Birth</th>
                    <th>Entries</th>
                    <th>TLDs Available</th>
                    <th>Status</th>
                    <th>BlueCoat</th>
                    <th>IBM X-Force</th>
                    <th>WatchGuard</th>
                    <th>Namecheap</th>
                    <th>Archive.org</th>
                 '''

    htmlTableBody = ''
    htmlTableFooter = '</table>'
    htmlFooter = '</body></html>'

    # Build HTML table contents
    for i in sortedDomains:
        htmlTableBody += '<tr>'
        htmlTableBody += '<td>{}</td>'.format(i[0]) # Domain
        htmlTableBody += '<td>{}</td>'.format(i[1]) # Birth
        htmlTableBody += '<td>{}</td>'.format(i[2]) # Entries
        htmlTableBody += '<td>{}</td>'.format(i[3]) # TLDs
        htmlTableBody += '<td>{}</td>'.format(i[4]) # Status

        htmlTableBody += '<td><a href="https://sitereview.bluecoat.com/" target="_blank">{}</a></td>'.format(i[5]) # Bluecoat
        htmlTableBody += '<td><a href="https://exchange.xforce.ibmcloud.com/url/{}" target="_blank">{}</a></td>'.format(i[0],i[6]) # IBM x-Force Categorization
        htmlTableBody += '<td><a href="http://www.borderware.com/domain_lookup.php?ip={}" target="_blank">WatchGuard</a></td>'.format(i[0]) # Borderware WatchGuard
        htmlTableBody += '<td><a href="https://www.namecheap.com/domains/registration/results.aspx?domain={}" target="_blank">Namecheap</a></td>'.format(i[0]) # Namecheap
        htmlTableBody += '<td><a href="http://web.archive.org/web/*/{}" target="_blank">Archive.org</a></td>'.format(i[0]) # Archive.org
        htmlTableBody += '</tr>'

    html = htmlHeader + htmlBody + htmlTableHeader + htmlTableBody + htmlTableFooter + htmlFooter
    logfilename = "{}.html".format(outputName)

    with open(logfilename,'w') as log:
        log.write(html)

    print("\n[*] Search complete")
    print("[*] Log written to {}\n".format(logfilename))
    
def main():
    ## Args Init
    args = initParser()

    login = args.login
    password = args.password
    
    alexa = args.alexa
    keyword = args.keyword
    check = args.check
    filename = args.filename
    maxresults = args.maxresults
    single = args.single
    timing = args.timing
    output = args.output
    maxwidth = args.maxwidth
    
    ## Domains URLs
    malwaredomainsURL = 'http://mirror1.malwaredomains.com/files/justdomains'
    expireddomainsloginURL = "https://member.expireddomains.net/login/"
    expireddomainsqueryURL = 'https://member.expireddomains.net/domain-name-search'  

    ## Headers
    useragent = 'Mozilla/5.0 (X11; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0'
    headers = {'User-Agent':useragent}

    # HTTP Session container, used to manage cookies, session tokens and other session information
    s = requests.Session()

    # Download known malware domains
    print('[*] Downloading malware domain list from {}\n'.format(malwaredomainsURL))
    maldomains = downloadMalwareDomains(malwaredomainsURL, headers, s)
    maldomainsList = maldomains.split("\n")

    # Retrieve reputation for a single choosen domain (Quick Mode)
    if single:
        checkDomain(single, maldomainsList, useragent, s)
        exit(0)

    # Perform detailed domain reputation checks against input file, print table, and quit. This does not generate an HTML report
    if filename:
        # Initialize our list with an empty row for the header
        data = []
        try:
            with open(filename, 'r') as domainsList:
                for line in domainsList.read().splitlines():
                    data.append(checkDomain(line,maldomainsList,useragent, s))
                    doSleep(timing)

                # Print results table
                header = ['Domain', 'BlueCoat', 'IBM X-Force']
                print(drawTable(header,data,maxwidth))

        except KeyboardInterrupt:
            print('Caught keyboard interrupt. Exiting!')
            exit(0)
        except Exception as e:
            print('[-] Error: {}'.format(e))
            exit(1)
        exit(0)


    # Lists for our ExpiredDomains results
    domain_list = []
    data = []
     
    # Create an initial session
    domainrequest = s.get("https://member.expireddomains.net",headers=headers)
    time.sleep(5)

    #Connect to expireddomains.net (auth)
    domainrequest = s.post(expireddomainsloginURL,{"login":login, "password":password}, headers=headers)
    time.sleep(5)
    
    # Generate list of URLs to query for expired/deleted domains
    urls = []
    
    # Use the keyword string to narrow domain search if provided. This generates a list of URLs to query

    if keyword:
        print('[*] Fetching expired or deleted domains containing "{}"'.format(keyword))
        for i in range (0,maxresults,25):
            if i == 0:
                urls.append("{}/?q={}&fwhois=22&ftlds[]=2&ftlds[]=3&ftlds[]=4&falexa={}".format(expireddomainsqueryURL,keyword,alexa))
                headers['Referer'] ='https://member.expireddomains.net/domain-name-search/?q={}&start=1'.format(keyword)
            else:
                urls.append("{}/?start={}&q={}&ftlds[]=2&ftlds[]=3&ftlds[]=4&fwhois=22&falexa={}".format(expireddomainsqueryURL,i,keyword,alexa))
                headers['Referer'] ='https://member.expireddomains.net/domain-name-search/?start={}&q={}'.format((i-25),keyword)
    
    # If no keyword provided, generate list of recently expired domains URLS (batches of 25 results).
    else:
        print('[*] Fetching expired or deleted domains...')
        numresults = int(maxresults / 2)
        for i in range (0,(numresults),25):
            urls.append('https://member.expireddomains.net/domains/combinedexpired?start={}&ftlds[]=2&ftlds[]=3&ftlds[]=4&falexa={}'.format(i,alexa))
 
    for url in urls:
        print("[*]  {}".format(url))
        domainrequest = s.get(url,headers=headers, cookies=genRandomCookie())
        domains = domainrequest.text

        temp = parseListDomain(domains, maldomainsList,keyword)
        if temp:
            domain_list = domain_list + temp
        temp = None 

        # Add additional sleep on requests to ExpiredDomains.net to avoid errors
        time.sleep(10)

        
    # Check for valid list results before continuing
    if len(domain_list) == 0:
        print("[-] No domain results found or none are currently available for purchase!")
        exit(0)
    else:
        domain_list_unique = []
        [domain_list_unique.append(item) for item in domain_list if item not in domain_list_unique]
        # Print number of domains to perform reputation checks against

        if check:
            print("\n[*] Performing reputation checks for {} domains".format(len(domain_list_unique)))
        
        for domain_entry in domain_list_unique:
            domain = domain_entry[0]
            birthdate = domain_entry[1]
            archiveentries = domain_entry[2]
            availabletlds = domain_entry[3]
            status = domain_entry[4]
            bluecoat = '-'
            ibmxforce = '-'
   
            # Perform domain reputation checks
            if check:
                
                bluecoat = checkBluecoat(domain, useragent, s)
                print("\t[+] {}: {}".format(domain, bluecoat))
                ibmxforce = checkIBMXForce(domain, useragent, s)
                print("\t[+] {}: {}".format(domain, ibmxforce))
                print("")
                # Sleep to avoid captchas
                doSleep(timing)
        
            # Append entry to new list with reputation if at least one service reports reputation
            if not ((bluecoat in ('Uncategorized','badurl','Suspicious','Malicious Sources/Malnets','captcha','Phishing','Placeholders','Spam','error')) \
                and (ibmxforce in ('Not found.','error'))):
                
                data.append([domain,birthdate,archiveentries,availabletlds,status,bluecoat,ibmxforce])
        

    # Sort domain list by column 2 (Birth Year)
    sortedDomains = sorted(data, key=lambda x: x[1], reverse=True) 

    if check:
        if len(sortedDomains) == 0:
            print("[-] No domains discovered with a desireable categorization!")
            exit(0)
        else:
            print("[*] {} of {} domains discovered with a potentially desireable categorization!".format(len(sortedDomains),len(domain_list)))

    # Print Text Table
    header = ['Domain', 'Birth', '#', 'TLDs', 'Status', 'BlueCoat', 'IBM']
    print(drawTable(header,sortedDomains, maxwidth))

    if output:
        genOutputFile(output, sortedDomains)

## MAIN
if __name__ == "__main__":
    main()
    







    
    
