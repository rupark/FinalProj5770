FROM ubuntu:20.10
RUN apt update -y

# Installing text editors
RUN apt install vim -y
RUN apt install emacs -y
RUN apt install nano -y
RUN apt install less -y

#Installing networking tools
RUN apt install curl -y
RUN apt install net-tools -y
RUN apt install netcat -y

#Installing Python3
RUN apt install python3 -y
RUN apt install python3-pip -y

#Library dependencies
RUN pip3 install BeautifulSoup4
RUN pip3 install requests
RUN pip3 install lxml

ADD wavs.py /
RUN chmod u+x /wavs.py
ENTRYPOINT ["/wavs.py"]

#ENTRYPOINT tail -f /dev/null
