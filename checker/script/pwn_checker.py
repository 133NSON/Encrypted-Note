#encoding=utf-8
import json
import zipfile
import paramiko
import uuid

from pwn import *


logger = logging.getLogger(__name__)
# FILE_PATH = os.path.dirname(os.path.abspath(__file__))
# logging.basicConfig(filename=os.path.join('/home/checker_project/logs', 'grpc.log'), level=logging.INFO,format="%(asctime)s %(levelname)s %(pathname)s %(funcName)s:%(lineno)d %(message)s")
# logging.basicConfig(filename=os.path.join('./', 'grpc.log'), level=logging.INFO,format="%(asctime)s %(levelname)s %(pathname)s %(funcName)s:%(lineno)d %(message)s")

STATUS_DOWN = 1
STATUS_UP = 0


class MYSSH(object):
	def __init__(self, host, port, rsa_key_path, pid):
		self.host = host
		self.port = port
		self.username = 'root'
		self.pkey = rsa_key_path
		self.pid = pid
		self.ssh, self.sftp = self.ssh_connect()

	def ssh_connect(self):
        ssh = None
        sftp = None
		try:
			ssh = paramiko.SSHClient()
			# private_key = paramiko.RSAKey.from_private_key_file(self.pkey)
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh.connect(hostname=self.host,
						port=self.port,
						username=self.username,
						# pkey=private_key,
                        pkey=self.pkey,
						timeout=5)
			sftp = paramiko.SFTPClient.from_transport(ssh.get_transport())
		except Exception as e:
			logger.error("connect ssh failed: %s Pid: %s", str(e), self.pid)
		return ssh, sftp

	def exec_command(self, command):
		# stdin, stdout, stderr = self.ssh.exec_command("export TERM=linux && export TERMINFO=/lib/terminfo  && {cmd}".format(cmd=command))
		stdin, stdout, stderr = self.ssh.exec_command(command)
		return stdout.read()

	def log(self, msg):
		logger.info('[+] %s Pid: %s', msg, self.pid)

	def GetRemoteFile(self, remote_file, local_file):
		try:
			self.sftp.get(remote_file, local_file)
			logger.info('get remote file success Pid: %s', self.pid)
		except Exception as e:
			logger.error("scp failed:" + str(e))

	def PutRemoteFile(self, local_file, remote_file):
		try:
			self.sftp.put(local_file, remote_file)
		except Exception as e:
			logger.error("scp failed: %s Pid: %s", str(e), self.pid)

	def close(self):
		try:
			self.ssh.close()
		except Exception as ex:
			pass


context.log_level = 'CRITICAL'
#context.log_level = 'debug'
current_dir = os.path.split(os.path.realpath(__file__))[0]

original_binary_path = os.path.join(current_dir, "./note")  # unpatched binary
#patched_binary_path = "./main_patched" # patched binary from player

ip = '127.0.0.1'
port = 9999


# patch_check是最基础的patch字节数、pltgot检测，注意调整patch limit，通防检测提供如下参考规则：
# 包括patch区域检测、通防检测（包括通用沙箱检测，注入检测）
# 可针对xinted配置文件、动态链接库、printenv && su pwnuser -c "printenv"环境变量是否被注入或修改做检测
def patch_check(patched_binary_path):
    origin_file = open(original_binary_path, 'rb')
    server_file = open(patched_binary_path, 'rb')
    a = origin_file.read()
    b = server_file.read()
    origin_file.close()
    server_file.close()

# check whether the file length is the same
    if len(a) != len(b):
            return {"status": STATUS_DOWN, "msg": "file length not correct!"}

# check whether the patched address is valid
    for i in range(len(a)):
        if a[i] != b[i]:
            if (i < 0x0000000000001F68 or i > 0x0000000000001F83) and (i < 0x0000000000001B34 or i >= 0x0000000000001B39) and (i < 0x0000000000001BA5 or i >= 0x0000000000001BAA) and (i < 0x0000000000001EDE or i >= 0x0000000000001EE3) and (i < 0x0000000000001D5A or i >= 0x0000000000001D5C):
                return {"status": STATUS_DOWN, "msg": "invalid patch address"}


# Check patchlimit
    diff_counter = 0
    i = 0
    while i < len(a):
            if a[i] != b[i]:
                    diff_counter += 1
            i += 1
    patch_limit = 0x24
    print(diff_counter)
    if diff_counter > patch_limit:
            return {"status": STATUS_DOWN, "msg": "patch too many bytes!"}

# check whether plt and got have been changed
    orig_elf = ELF(original_binary_path)
    patch_elf = ELF(patched_binary_path)

    for (key, value) in orig_elf.got.items():
            if orig_elf.read(value, 8) != patch_elf.read(value, 8):
                    return {"status": STATUS_DOWN, "msg": "can't patch got"}

    for (key, value) in orig_elf.plt.items():
            if orig_elf.read(value, 8) != patch_elf.read(value, 8):
                    return {"status": STATUS_DOWN, "msg": "can't patch plt"}

    return {"status": STATUS_UP, "msg": "good"}

# 脚本多线程运行，注意关闭io，不能出现全局变量（使用局部变量），注意check填充数据的随机性
# 对于每一个check失败的点，需要返回具体失败原因
def functionality_check(ip, port):

    l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
    l32 = lambda      :u32(io.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
    rl = lambda	a=False		: io.recvline(a)
    ru = lambda a,b=True	: io.recvuntil(a.encode(),b)
    rn = lambda x			: io.recvn(x)
    sn = lambda x			: io.send(x.encode())
    sl = lambda x			: io.sendline(x.encode())
    sa = lambda a,b			: io.sendafter(a.encode(),b.encode())
    sla = lambda a,b		: io.sendlineafter(a.encode(),b.encode())
    irt = lambda			: io.interactive()
    dbg = lambda text=None  : gdb.attach(io, text)
    lg = lambda s			: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
    uu32 = lambda data		: u32(data.ljust(4, b'\x00'))
    uu64 = lambda data		: u64(data.ljust(8, b'\x00'))
    ur64 = lambda data		: u64(data.rjust(8, b'\x00'))

    def rand_string(l):
        return ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(l))

    def menu(choice):
        sla('choice: ', str(choice))

    def add(idx, size, content):
        menu(1)
        sla('index: ', str(idx))
        sla('size: ', str(size))
        sa('content: ', content)

    def show(idx):
        menu(2)
        sla('index: ', str(idx))

    def delete(idx):
        menu(3)
        sla('index: ', str(idx))

    try:
        # connect to host
        io = remote(ip, port,timeout=2)
        if not io:
            return {"status": STATUS_DOWN, "msg": "connection error"}

        sendstr = 'Mai'
        sla('Username: ',sendstr)
        re1 = ru(sendstr,False)
        if sendstr.encode() not in re1:
            io.close
            return {"status": STATUS_DOWN, "msg": b"name error"}
        sla('Password: ','1202')

        sendstr = rand_string(0x13)
        add(7, 0x30, sendstr + '\n')
        show(7)
        re2 = ru(sendstr, False)
        if sendstr.encode() not in re2:
            io.close
            return {"status": STATUS_DOWN, "msg": b"note7 error"}

        sendstr = rand_string(7)
        add(0, 8, sendstr + '\n')
        show(0)
        re3 = ru(sendstr, False)
        if sendstr.encode() not in re3:
            io.close
            return {"status": STATUS_DOWN, "msg": b"note0 error"}
        delete(0)

        sendstr = rand_string(0x5f)
        add(5, 0x60, sendstr + '\n')
        show(5)
        re4 = ru(sendstr, False)
        if sendstr.encode() not in re4:
            io.close
            return {"status": STATUS_DOWN, "msg": b"note5 error"}

        delete(5)
        delete(7)
        show(5)
        show(7)
        delete(3)
        menu(1)
        sla('index: ', str(8))
        menu(4)

    except Exception as ex:
        if io:
            io.close()
        return {"status": STATUS_DOWN, "msg": ex}
    try:
        if io:
            io.close()
    except Exception as e:
        logger.info('function except error: %s' % (e))
        pass

    return {"status": STATUS_UP, "msg": "good"}

def free_check(key_file_name, ip, port):

    l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
    l32 = lambda      :u32(io.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
    rl = lambda	a=False		: io.recvline(a)
    ru = lambda a,b=True	: io.recvuntil(a.encode(),b)
    rn = lambda x			: io.recvn(x)
    sn = lambda x			: io.send(x.encode())
    sl = lambda x			: io.sendline(x.encode())
    sa = lambda a,b			: io.sendafter(a.encode(),b.encode())
    sla = lambda a,b		: io.sendlineafter(a.encode(),b.encode())
    irt = lambda			: io.interactive()
    dbg = lambda text=None  : gdb.attach(io, text)
    lg = lambda s			: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
    uu32 = lambda data		: u32(data.ljust(4, b'\x00'))
    uu64 = lambda data		: u64(data.ljust(8, b'\x00'))
    ur64 = lambda data		: u64(data.rjust(8, b'\x00'))

    def rand_string(l):
        return ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(l))

    def menu(choice):
        sla('choice: ', str(choice))

    def add(idx, size, content):
        menu(1)
        sla('index: ', str(idx))
        sla('size: ', str(size))
        sa('content: ', content)

    def show(idx):
        menu(2)
        sla('index: ', str(idx))

    def delete(idx):
        menu(3)
        sla('index: ', str(idx))

    try:
        keyfile = open(key_file_name, 'r')
        private_key = paramiko.RSAKey.from_private_key(keyfile)
        # get pid infomation
        s = paramiko.SSHClient()
        s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        s.connect(hostname=ip, port=port, username='root', pkey=private_key)  #
        stdin, stdout, stderr = s.exec_command(
            "lsof -i:8888|grep "+local+"|grep  -v 'timeout' |awk '{print $2}'|head -n 1")
        checker_pwn_pid = stdout.read().decode().strip()
        # connect to host
        io = remote(ip, port,timeout=2)
        if not io:
            return {"status": STATUS_DOWN, "msg": "connection error"}

        sla('Username: ','Mai')
        sla('Password: ','1202')

        # initialize heap
        sendstr = rand_string(0x13)
        add(7, 0x30, sendstr + '\n')
        delete(7)

        # heap info
        stdin, stdout, stderr = s.exec_command(
            "cat /proc/{0}/maps".format(checker_pwn_pid))
        map_info = stdout.read().decode().split('\n')
        heap_info = ''
        if '[heap]' in map_info[3]:
            heap_info = map_info[3]
        else:
            for i in map_info:
                if '[heap]' in i:
                    heap_info = i
                    # print('123123')
        # malloc may be nopped
        if heap_info == '':
            return False

        # heap addr
        heap_addr_start, heap_addr_end = [int(i, 16) for i in re.match(
            "\w*-\w*", heap_info).group(0).split('-')]
        # print(heap_addr_start, heap_addr_end)
        # print(heap_info)

        # if free is there, heap should be tcachebins[0x50]->freed_chunk
        with sftp.file("/proc/{0}/mem".format(checker_pwn_pid), mode='rb') as file:
            file.seek(heap_addr_start+0xa8)
            t_fd = int(str(u64(file.read(8))[0]), 10)
            if (t_fd != (heap_addr_start+0x340)):
                return {"status": STATUS_DOWN, "msg": b"free is nopped"}
    except Exception as ex:

        if io:
            io.close()
        return {"status": STATUS_DOWN, "msg": ex}
    try:
        if io:
            io.close()
    except Exception as e:
        logger.info('function except error: %s' % (e))
        pass

    return {"status": STATUS_UP, "msg": "good"}

# 若附件需要运行，请主动赋予可执行权限；所有涉及文件路径的必须使用绝对路径
def checker(key_file_name, ip, **kwargs):
    logger.info('[ 入参 ] ip: %s, kwargs: %s' % (ip, kwargs))
    pid = kwargs.get("pid")
    zf = zipfile.ZipFile(os.path.join(json.loads(kwargs['attachments']).get('note.zip')))
    zf.extractall(current_dir)
    logger.info('[ 脚本目录列表 ] %s Pid: %s', os.listdir(current_dir), pid)

    for i in range(2):
        uuid_str = uuid.uuid4().hex
        tmp_file = '/tmp/tmpfile_{}.tmp'.format(uuid_str)
        check = None
        try:
            #check = MYSSH(ip, 22, os.path.join(current_dir, "./id_rsa_pem"), pid)
            check = MYSSH(ip, 22, "5MTkGkQqP8x@",pid)
            check.GetRemoteFile('/home/ctf/challenge/note', tmp_file)
            a = patch_check(tmp_file)
            if a["status"] == STATUS_DOWN:
                return {"status": STATUS_DOWN, "msg": a["msg"]}
            logger.info('patch_check success')
            a = functionality_check(ip, 9999)
            if a["status"] == STATUS_DOWN:
                return {"status": STATUS_DOWN, "msg": a["msg"]}
            logger.info('functionality_check success')
            return {"status": STATUS_UP, "msg": "good"}
        except Exception as e:
            return {"status": STATUS_DOWN, "msg": e}
        finally:
            os.system("rm " + tmp_file)
            if check and check.ssh:
                check.close()
    return {"status": STATUS_DOWN, "msg": "down"}

#用于check时间较长且随机错误性较高的题目，循环尝试
#def checker(ip, **kwargs):
#	ck = checker01(ip,kwargs)
#	if ck['status'] != STATUS_UP:
#		return checker01(ip,kwargs)
#	else:
#		return ck

if __name__ == '__main__':
	#print(functionality_check("192.168.190.135", 9999))
	print(checker("192.168.190.135", **{'attachments': json.dumps({'note.zip': './note.zip'})}))

