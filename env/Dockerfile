FROM ubuntu:20.04

#LABEL maintainer="d1ag0n@cyberpeace.cn"

WORKDIR /opt
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.ustc.edu.cn/g" /etc/apt/sources.list && \
    sed -i "s/deb http:\/\/se/#/g" /etc/apt/sources.list && \
    sed -i "s/deb-src http:\/\/se/#/g" /etc/apt/sources.list && \
    apt-get update 

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get install -y lib32z1 xinetd libc6-dev-mips64el-cross libc6-dev-arm64-cross qemu-user-static libc6-dev-armel-cross \
    openssh-server unzip make wget bison flex build-essential  curl python-dev libpcap-dev python2.7 libpython2.7 \
    libc6-dbg inetutils-ping libreadline-dev \
    && rm -rf /var/lib/apt/lists/*

COPY ./get-pip.py /opt/
RUN python get-pip.py && rm -rf /opt/get-pip.py

ADD ./kafel-master.zip /opt/
RUN unzip kafel-master.zip && rm kafel-master.zip && mv kafel-master kafel && cd kafel && make 

COPY ./xinetd /usr/sbin/xinetd

# 开启ssh登录
RUN rm -f /etc/service/sshd/down
RUN sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config &&\
    sed -ri 's/#UseDNS\ no/UseDNS\ no/g' /etc/ssh/sshd_config && \
    sed -ri "s/StrictModes yes/StrictModes no/g" /etc/ssh/sshd_config && \
    sed -ri "s/UsePAM yes/UsePAM no/g" /etc/ssh/sshd_config

# 设置允许密码登录
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# 设置只可公钥登录
# RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config

## 安装抓包的flow_dumper.py所需依赖
RUN pip install dpkt==1.8.8 \
    pcapy==0.11.1 \
    impacket==0.9.15 \
    supervisor==3.3.1 \
    pyinotify==0.9.6 \
    requests \
    # pwntools \
    -i https://pypi.tuna.tsinghua.edu.cn/simple

# 添加选手用户
RUN groupadd ctf && \
    useradd -g ctf ctf -m && \
    echo "ctf:xxxxxxxx" | chpasswd && \
    echo "root:xxxxxxxx" | chpasswd

# 添加题目用户
RUN useradd pwnuser

RUN echo_supervisord_conf > /etc/supervisord.conf
RUN mkdir /etc/supervisord.conf.d
RUN echo "[include]" >> /etc/supervisord.conf
RUN echo "files = /etc/supervisord.conf.d/*.ini" >> /etc/supervisord.conf
COPY ./flow/flow_dumper.ini /etc/supervisord.conf.d
COPY ./flow/flow_dumper.py /root
COPY ./flow/container_mon.py /root

# 编译并设置赛题所属组和权限
WORKDIR /home/ctf/challenge

COPY ./bin /home/ctf/challenge
RUN chown -R root:ctf /home/ctf/challenge && \
	chmod -R 775 /home/ctf/challenge && \
	mkdir /home/ctf/.ssh

WORKDIR /home/ctf

RUN echo "ctf{this_is_a_sample_flag}" > /home/ctf/flag
RUN chmod 644 /home/ctf/flag && chown root:root /home/ctf

# RUN cp -R /lib* /home/ctf
RUN cp -R /usr/lib* /home/ctf

RUN mkdir /home/ctf/dev && \
	mknod /home/ctf/dev/null c 1 3 && \
	mknod /home/ctf/dev/zero c 1 5 && \
	mknod /home/ctf/dev/random c 1 8 && \
	mknod /home/ctf/dev/urandom c 1 9 && \
	chmod 666 /home/ctf/dev/*

RUN mkdir /home/ctf/bin && \
	cp /bin/sh /home/ctf/bin && \
	cp /bin/ls /home/ctf/bin && \
	cp /bin/cat /home/ctf/bin

COPY ./xinetd.cfg /etc/xinetd.d/ctf
# 搅屎测试的
# COPY ./kill.cfg /etc/xinetd.d/testkill
# COPY ./noalarm.cfg /etc/xinetd.d/noalarm
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail

ADD pwn.kafel /etc/pwn.kafel

COPY ./start.sh /start.sh
RUN chmod +x /start.sh

# 运维使用，添加了运维人员的公钥
RUN mkdir /root/.ssh
RUN echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtYBQRQ4uoo5kRyFQaGICnIF4aoxv8L+5FzgbBzemzibSPisnXTCPXpG4zISUpT6cGmtf3yVJErlzSYBU6NoOGXqj3zl0JsLMb0KC9MNnXLkNKsFabURJOdQWixXGsn9TS3r1vDfhTYKUCo2IRuCKlCoXMYWGJ3QTXqa4itgntI71Zi8/a8OSsdT10jaDk4M0xCdToPfQ18uzVmyNekqKyZor7wZr/OUpXzJTivnvTk3FHAzgetHXGpFr07FEAfFrI15WLzZvTPRM3gGn8m6jVkhMHegm6OK8s6UTuLvGSP+9B27UmJN4lvq8JTtTZIJ8qKgahg41+0/pumLMCYxox root@ubuntu' >> /root/.ssh/authorized_keys 
RUN chmod 600 /root/.ssh/authorized_keys

CMD ["/start.sh"]
