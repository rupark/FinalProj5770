# README

Welcome to the WAVS Readme! WAVS will identify XSS, XSRF, and cookie caching vulnerabilities in the
URL you pass it. Adding -c will crawl the first 100 links in the domain. URL's must include
http:// or https://.

## To run with Docker:
```
docker build -t wavs .
docker run wavs {URL} {OPTIONAL: -c}
```

##If you do not want to run with Docker:
First, install BeautifulSoup4, requests, and lxml.
```
./wavs {URL} {OPTIONAL: -c}
```
