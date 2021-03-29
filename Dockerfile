FROM python:slim
RUN echo \
  deb http://mirrors.aliyun.com/debian/ buster main non-free contrib\
  deb-src http://mirrors.aliyun.com/debian/ buster main non-free contrib\
  deb http://mirrors.aliyun.com/debian-security buster/updates main\
  deb-src http://mirrors.aliyun.com/debian-security buster/updates main\
  deb http://mirrors.aliyun.com/debian/ buster-updates main non-free contrib\
  deb-src http://mirrors.aliyun.com/debian/ buster-updates main non-free contrib\
  deb http://mirrors.aliyun.com/debian/ buster-backports main non-free contrib\
  deb-src http://mirrors.aliyun.com/debian/ buster-backports main non-free  contrib\
  > /etc/apt/sources.list
RUN apt-get update && \
    apt-get install git -y && \
		apt-get install libffi-dev && \
    apt-get install python-gevent -y && \
		apt-get clean
WORKDIR /root/.pip
RUN echo \
	[global] \
	index-url = http://pypi.douban.com/simple \
	> ~/.pip/pip.conf
CMD ["export", "http_proxy=http://xx.xx.xx.xx:7890"]
CMD ["export", "https_proxt=http://xx.xx.xx.xx:7890"]
CMD ["export", "all_proxt=socks5://xx.xx.xx.xx:7891"]
RUN mkdir /onlinetools
COPY ./* /onlinetools
WORKDIR /onlinetools
RUN pip install -r requirements.txt && \
    rm -fr ~/.cache/pip
EXPOSE 8000
CMD ["python","/onlinetools/main.py"]
