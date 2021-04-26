#!/usr/bin/env python3

# WAVS is a web application vulnerability scanner that supports detection for
# reflected XSS, XSRF/CSRF, and cacheable cookies

import sys
import requests
from bs4 import BeautifulSoup
import json


start_url = sys.argv[1]
if 'http' not in start_url:
    print('Please pass in a url that begins with http:// or https://')
    exit()
base_parts = start_url.split('/')
base = base_parts[0] + '//' + base_parts[2] + '/'

#Used for sending dummy data during CSRF Detection
example_inputs = {"text": "abcdefgh",
"email": "test@gmail.com",
"password": "abcd1234",
"checkbox": "true",
"radio": "1",
"datetime": "1999-09-10T23:59:60Z",
"datetime-local":
"1998-04-26T23:20:50.52",
"date": "1999-09-10",
"month": "1999-09",
"time": "14:38:00",
"week": "1999-W16",
"number": "123456",
"range": "1.23",
"url": "http://localhost/",
"search": "example",
"tel": "012345678",
"color": "#FFFFFF",
"hidden": "Secret",
"submit": ""}

#Used for holding what links we've crawled already
seen = []
#Links that still have to be crawled
frontier = []
#To begin, the frontier is the passed in url
frontier.append(start_url)

#Keep crawling until the frontier is empty or we've crawled 100 links
while frontier != [] and len(seen) < 100:
    try:
        #Needed to get a 200 response
        headers = {'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'}

        url = frontier[0]
        if 'http' not in frontier[0] and 'https' not in frontier[0]:
            url = base + frontier[0]

        seen.append(url)
        reqs = requests.get(url)
        post_url = url

        #For vulnsrv, need to send POST requests to 'send' endpoint
        if '?' in url or url[-1] == '/':
            post_url = url.split('?')[0] + 'send'

        if reqs.status_code == 200:
            soup = BeautifulSoup(reqs.text, 'lxml')

            if len(sys.argv) > 2:
                #Web crawling!
                if sys.argv[2] == '-c':
                    for link in soup.find_all(["a"]):
                        try:
                            link_name = link['href']

                            if 'https' not in link_name and 'http' not in link_name and link_name not in frontier and link_name not in seen:
                                frontier.append(link_name.strip('/'))
                        except Exception as e:
                            print('Site Error for ' + url + ': ' + str(e) + '. Continuing...')
                            pass

            #Cross Site Scripting Checking, check if XSS_Warning apppears in the response
            XSS_STRING = u'<script>alert("XSS_Warning");</script>'

            # sprint(post_url)

            #Some websites employ XSRF tokens or sessionIDs; have to handle in order to get successsful POST
            token = '1'
            try:
                token = reqs.headers['Set-Cookie'].split(' ')[0].strip('sessionID="').strip('";')
            except Exception as e:
                print('Site Error for ' + url + ': ' + str(e) + '. Continuing...')
                pass
            vulnerable_inputs = []

            for form in soup.find_all(["form"]):
                inputs = form.find_all('input')

                # Send POST request for each input, see if 'XSS_Warning' is in response
                for input in inputs:
                    try:
                        if input['type'] != 'submit' and input['type'] == 'text' or input['type'] == 'password':
                            to_send = {}
                            to_send['csrfToken'] = token
                            name = input['name']
                            to_send[name] = XSS_STRING
                            fake_headers = headers
                            fake_headers['Cookie'] = 'sessionID=' + token
                            response = requests.post(post_url, data=to_send, headers=headers)
                            if response.status_code == 200:
                                if 'XSS_Warning' in str(response.content) and input['name'] not in vulnerable_inputs:
                                    vulnerable_inputs.append(input['name'])
                                    print('*****XSS: ' + url + " is vulnerable for input " + input['name'])
                    except Exception as e:
                        print('Site Error for ' + url + ': ' + str(e) + '. Continuing...')
                        pass

            #CSRF
            #Get forms, send all inputs but hidden ones (could be tokens), see if still works (ie CSRF isnt being used at all or incorrectly)
            CSRF_params = {}
            for form in soup.find_all(["form"]):
                inputs = form.find_all('input')
                for input in inputs:
                    try:
                        if input['type'] != 'hidden' and input['type'] != 'submit':
                            CSRF_params[input['name']] = example_inputs[input['type']]
                    except Exception:
                        pass
                response = requests.post(post_url, data=CSRF_params, headers=headers)
                if response.status_code == 200:
                    print('*****CSRF: ' + url + " is vulnerable")
                    break

            #Checking for cacheable cookies
            headers = reqs.request.headers

            try:
                if "Set-Cookie" in headers or 'Set-Cookies' in headers:
                    if "Cache-Control" in headers:
                        cache_vals = headers['Cache-Control']
                        #max-age 0 is essentially same thing as no-cache
                        if not (("no-cache" in cache_vals or 'private' in cache_vals) or ("max-age" in cache_vals and '0' in cache_vals)):
                            #Not Secure
                            print('*****Implicit Cacheable Cookies')
                    else:
                        #Not Secure
                        print('*****Implicit Cacheable Cookies')
            except Exception as e:
                print('Site Error for ' + url + ': ' + str(e) + '. Continuing...')
                pass
    except Exception as e:
        print('Site Error for ' + url + ': ' + str(e) + '. Continuing...')
        pass

    frontier.pop(0)
