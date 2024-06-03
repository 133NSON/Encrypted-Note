#!/bin/sh

service ssh restart;
/etc/init.d/xinetd start;
supervisord -c /etc/supervisord.conf;
sleep infinity;

