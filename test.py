#!/usr/bin/env python
from __future__ import print_function

from subprocess import STDOUT
from plumbum import local
import os, sys, re, time

tmp = 'zone_file.example.tmp'
local['cp']('zone_file.example', tmp)

server, client = local['./tddu-server.py'], local['./tddu-client.py']

# To add extra loopback IPs use:
#  ip addr add 127.0.0.2 dev lo
#  ip addr add ::2 dev lo
ip_changes = [
	'127.0.0.1', '::1',
	'127.0.0.2', '127.0.0.1', '127.0.0.1',
	'::2', '::2',
	'127.0.0.2'
]

with open('zone_file.example') as src:
	keys = re.findall('skey(?:[^:\n]+)?: (\S+)', src.read())

def print_output(out, prefix):
	if not out: return
	for line in out.rstrip('\n').split('\n'):
		print('{}: {}'.format(prefix, line.rstrip()))
	print()

args = ['--debug', 'zone_file.example.tmp']
print('S% ./tddu-server.py {}\n'.format(' '.join(args)))
server_n, server = None, server.popen(args, stderr=STDOUT)
time.sleep(2) # give server some time to start

try:
	for dst in ip_changes:
		args = ['--debug', '{}:5533'.format(dst)] + keys
		print('C% ./tddu-client.py {}'.format(' '.join(args)))
		n, out, err = client.run(args, stderr=STDOUT)
		assert not n and not err, [n, out, err]
		print_output(out, 'C')

		time.sleep(0.5) # give server some time to process packet
		server_n = server.poll()
		if server_n is not None: break

finally:
	if server_n is None: server.terminate()
	server.wait()
	print_output(server.stdout.read(), 'S')
	if server_n is not None: sys.exit(1)

with open(tmp, 'rb') as src: src = src.read()
for line in [
		'+some.static.name:213.180.193.3',
		'+some.random.name:127.0.0.2',
		'+extra.random.name:127.0.0.2',
		'6some.random.name:00000000000000000000000000000002',
		'+another.static.name:93.158.134.3',
		'6another.static.name:2a0206b8000000000000000000000003' ]:
	assert re.search(r'(^|\s){}\n'.format(re.escape(line)), src), line

print('Done')
