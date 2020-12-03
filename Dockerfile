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
		apt-get clean
WORKDIR /root/.pip
RUN echo \
	[global]\
	index-url = http://pypi.douban.com/simple\
	> ~/.pip/pip.conf
RUN git clone  https://github.com/HexChristmas/onlinetools /onlinetools
RUN pip install -r requirements.txt && \
    rm -fr ~/.cache/pip
EXPOSE 8000
CMD ["python","/onlinescan/main.py"]
