#!/usr/bin/env python
from __future__ import print_function

from subprocess import STDOUT
from plumbum import local
import os, sys, re, time

local['cp']('zone_file.example', 'zone_file.example.tmp')

server, client = local['./tddu-server.py'], local['./tddu-client.py']

ip_changes = [
	'127.0.0.1', '::1',
	'127.0.0.2', '127.0.0.1', '127.0.0.1',
	'::2', '::2'
]

with open('zone_file.example') as src:
	keys = re.findall('skey: (\S+)', src.read())

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

print('Done')
