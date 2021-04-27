# README

Welcome to the WAVS Readme! WAVS will identify XSS, XSRF, and cookie caching vulnerabilities in the
URL you pass it. Adding -c will crawl the first 100 links in the domain. URLs must include
http:// or https://.

If you are interested in testing it out on vulnsrv, you can download and run vulnsrv on you local machine from here: https://github.com/phihag/vulnsrv. Then run WAVS using the non-Docker command.

## To run with Docker:
```
docker build -t wavs .
docker run wavs {URL} {OPTIONAL: -c}
Example: docker run wavs https://canvas.northeastern.edu -c
```

## If you do not want to run with Docker:
First, install BeautifulSoup4, requests, and lxml.
```
./wavs.py {URL} {OPTIONAL: -c}
Example: ./wavs.py https://canvas.northeastern.edu -c
```
