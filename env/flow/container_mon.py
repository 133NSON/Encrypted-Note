# Encoding=utf-8
import logging
from threading import Thread
import time
import os

# log path
LOG_PATH = "/var/log/container_mon.log"
SET_SLEEP_TIME = 0.1

# 单个最大文件限制
MAX_SIGNLE_FILE_SIZE = 1024 * 1024 * 1000
# 总大小限制
MAX_TOTAL_FILE_SIZE = 1024 * 1024 * 1500
# 进程数目限制
MAX_PROCESS_COUNT = 50

mon_dir_list = ['/var/www/html', '/tmp']


class ContainerMon(Thread):
    def __init__(self, mon_dir_list):
        super(ContainerMon, self).__init__()
        self.mon_dir_list = mon_dir_list

    def mygetsize(self, path):
        size = os.path.getsize(path)
        size = (size / 4096 + 1) * 4096
        return size

    def get_dir_size(self, dirpath):
        total_szie = 0
        for root, dirs, files in os.walk(dirpath):
            for file in files:
                total_szie += self.mygetsize(os.path.join(root, file))
            for dir in dirs:
                # pass
                total_szie += 4096
        return total_szie

    def process_check(self):
        # 结束同一批大量链接
        proc_count = int(os.popen("ps -ef|grep pwnuser|wc -l").read().strip())
        if proc_count > MAX_PROCESS_COUNT:
            logging.info("MAX_PROCESS_COUNT:{c}".format(c=proc_count))
            os.system("ps -ef|grep pwnuser|awk '{print $2}' |xargs kill -9")
        xinetd_count = int(os.popen("ps -ef|grep xinetd|wc -l").read().strip())
        if xinetd_count == 2:
            os.system("service xinetd stop")
            os.system("service xinetd start")
        # 结束长连接
        cmd = "ps -A -opid,etimes,uname|grep pwnuser|awk '{if($2>40) print $1}' | xargs kill -9"
        os.system(cmd)

    def size_check(self):
        for i in mon_dir_list:
            size = self.get_dir_size(i)
            if size > MAX_TOTAL_FILE_SIZE:
                logging.info("MAX_TOTAL_FILE_SIZE:{dir} {size}".format(
                    dir=i, size=size))
                os.system('service apache2 stop')

    def run(self):
        while 1:
            try:
                # self.size_check()
                self.process_check()
            except Exception as e:
                logging.error("Exception: %s" % str(e))
            finally:
                time.sleep(SET_SLEEP_TIME)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-5.5s : %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename=LOG_PATH or None)
    logging.info("Starting container  monitor...")

    mon_thread = ContainerMon(mon_dir_list)
    mon_thread.start()
