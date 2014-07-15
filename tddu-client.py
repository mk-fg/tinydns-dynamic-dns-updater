#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import os, sys, types, re, socket, struct, time, random

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import URLSafeBase64Encoder
from nacl.hash import sha256


key_id_len = 28
sig_len = 64
msg_data_fmt = '!{}sd'.format(key_id_len)
msg_data_len = struct.calcsize(msg_data_fmt)
msg_fmt = '{}s{}s'.format(msg_data_len, sig_len)
msg_len = struct.calcsize(msg_fmt)

default_port = 5533


class AddressError(Exception): pass

def get_socket_info( host,
		port=0, family=0, socktype=0, protocol=0,
		force_unique_address=None, pick_random=False ):
	log_params = [port, family, socktype, protocol]
	log.debug('Resolving addr: %r (params: %s)', host, log_params)
	host = re.sub(r'^\[|\]$', '', host)
	try:
		addrinfo = socket.getaddrinfo(host, port, family, socktype, protocol)
		if not addrinfo: raise socket.gaierror('No addrinfo for host: {}'.format(host))
	except (socket.gaierror, socket.error) as err:
		raise AddressError( 'Failed to resolve host:'
			' {!r} (params: {}) - {} {}'.format(host, log_params, type(err), err) )

	ai_af, ai_addr = set(), list()
	for family, _, _, hostname, addr in addrinfo:
		ai_af.add(family)
		ai_addr.append((addr[0], family))

	if pick_random: return random.choice(ai_addr)

	if len(ai_af) > 1:
		af_names = dict((v, k) for k,v in vars(socket).viewitems() if k.startswith('AF_'))
		ai_af_names = list(af_names.get(af, str(af)) for af in ai_af)
		if socket.AF_INET not in ai_af:
			log.fatal(
				'Ambiguous socket host specification (matches address famlies: %s),'
					' refusing to pick one at random - specify socket family instead. Addresses: %s',
				', '.join(ai_af_names), ', '.join(ai_addr) )
			raise AddressError
		(log.warn if force_unique_address is None else log.info)\
			( 'Specified host matches more than one address'
				' family (%s), using it as IPv4 (AF_INET)', ai_af_names )
		af = socket.AF_INET
	else: af = list(ai_af)[0]

	for addr, family in ai_addr:
		if family == af: break
	else: raise AddressError
	ai_addr_unique = set(ai_addr)
	if len(ai_addr_unique) > 1:
		if force_unique_address:
			raise AddressError('Address matches more than one host: {}'.format(ai_addr_unique))
		log.warn( 'Specified host matches more than'
			' one address (%s), using first one: %s', ai_addr_unique, addr )

	return af, addr


def key_encode(key):
	return key.encode(URLSafeBase64Encoder)

def key_decode(string, t=VerifyKey):
	return t(string, URLSafeBase64Encoder)

def key_decode_signing(string):
	return key_decode(string, t=SigningKey)

def key_get_id(verify_key):
	return '{{:>{}s}}'.format(key_id_len).format(
		sha256(verify_key.encode(), URLSafeBase64Encoder)[:key_id_len] )

def key_check_sig(key, msg_data, msg_sig):
	try: key.verify(msg_data, msg_sig)
	except BadSignatureError: return False
	else: return True


def build_msg(key, ts=None, key_id=None):
	if ts is None: ts = time.time()
	if key_id is None: key_id = key_get_id(key.verify_key)
	msg_data = struct.pack(msg_data_fmt, key_id, ts)
	msg_sig = key.sign(msg_data).signature
	assert len(msg_sig) == sig_len, [msg_sig, sig_len]
	return struct.pack(msg_fmt, msg_data, msg_sig)

def dispatch_packets( dsts, binds, keys,
		ts=None, family=socket.AF_UNSPEC, random_addr=False ):
	msgs = list(build_msg(key, ts, key_id) for key_id, key in keys.viewitems())

	for dst, bind in it.product(dsts, binds):
		dst_af = family

		if bind:
			match = re.search('^(.*):(\d+)$', bind)
			host, port = match.groups() if match else (bind, 0)
			bind_socktype, bind_port = socket.SOCK_DGRAM, int(port)
			bind_af, bind_addr = get_socket_info(
				host, bind_port, family=family, socktype=bind_socktype )
			if dst_af == socket.AF_UNSPEC: dst_af = bind_af

		try: host, port = dst.rsplit(':', 1)
		except ValueError: host, port = dst, default_port
		dst_socktype, dst_port = socket.SOCK_DGRAM, int(port)
		dst_af, dst_addr = get_socket_info( host, dst_port,
			family=dst_af, socktype=dst_socktype, pick_random=random_addr )

		log.debug(
			'Sending %s update msg(s) to: %r (port: %s, af: %s, socktype: %s, bind: %s)',
			len(msgs), dst_addr, dst_port, dst_af, dst_socktype, bind )

		sock = socket.socket(dst_af, dst_socktype)
		if bind:
			assert bind_af == dst_af and bind_socktype == dst_socktype,\
				[bind_af, dst_af, bind_socktype, dst_socktype]
			log.debug('Binding sending socket to: %r (port: %s)', bind_addr, bind_port)
			sock.bind((bind_addr, bind_port))

		for msg in msgs: sock.sendto(msg, (dst_addr, dst_port))



def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		usage='%(prog)s [options]', # argparse fails to build that for $REASONS
		description='Tool to update tinydns zone file entries for host remotely.')

	parser.add_argument('destination', nargs='?',
		help=(
			'Address/port to of the remote listening udp socket'
				' to send update information to, in "host[:port]" format'
				' (where port defaults to {}, if omitted).'
			' Multiple destinations can be specified, separated by slash ("/").'
		).format(default_port))

	parser.add_argument('key', nargs='*',
		help='Ed25519 signing key or absoulte path to a file'
				' with one or more (separated by spaces/newlines) keys to use for client id.'
			' Can be specified multiple times to use multiple keys/files'
				' at the same time, sending one update to dst host for each key.'
			' --genkey option can be used to generate signing/verify keypairs suitable'
				' for use on destination host (only verify key is needed there) and with this'
				' script (signing key).')

	parser.add_argument('-g', '--genkey', action='store_true',
		help='Generate a new random signing/verify'
			' Ed25519 keypair, print both keys to stdout and exit.')

	parser.add_argument('-b', '--bind', metavar='host[:port]',
		help='Host/port to bind sending socket to.'
			' Can be useful for firewall rules and to explicitly bind to external interface.'
			' Enclose IPv6 into square brackets to avoid'
				' last word of it from being processed as a port number.'
			' Multiple sources can be specified, separated by slash ("/").'
			' Examples: 1.2.3.4:8793, [2a02:6b8::3]/213.180.204.3')
	parser.add_argument('-v', '--ip-af',
		metavar='{ 4 | 6 }', choices=('4', '6'), default=socket.AF_UNSPEC,
		help='Resolve hostname(s) (if any) using specified address family version.'
			' Either "4" or "6", no restriction is appled by default.')
	parser.add_argument('-r', '--random-addr', action='store_true',
		help='Pick random address from those returned by getaddrinfo() for destination.'
			' Default is to throw error if several addresses are returned.')

	parser.add_argument('-n', '--packets',
		metavar='n', type=int, default=1,
		help='Number of UDP packets to dispatch (default: %(default)s).')
	parser.add_argument('--send-delay',
		metavar='{ n | n:next }', default='1:mul:2',
		help='Delay between dispatched packets.'
			' Can be specified either simply as "n" (float) or as "n:next", where "next"'
					' is an operator (see python "operator" module) to use to calculate each next delay'
					' and possible args to it (separated by colon(s)).'
				' Examples: 2.5 (2.5, 2.5, ...), 1:mul:2 (1, 2, 4, 8, ...),'
					' 1:add:5 (1, 6, 11, 16, ...), 10:sub:1 (10, 9, 8, ...). Default: %(default)s)')

	parser.add_argument('-d', '--debug', action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	import logging
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = logging.getLogger()

	if opts.genkey:
		signing_key = SigningKey.generate()
		print('Signing key (for this script only):\n  ', key_encode(signing_key), '\n')
		print('Verify key (to use on server):\n  ', key_encode(signing_key.verify_key), '\n')
		return

	if not opts.key: parser.error('At least one key must be specified')
	if not opts.destination: parser.error('Destination endpoint must be specified')
	else: opts.destination = opts.destination.split('/')
	opts.bind = [None] if not opts.bind else opts.bind.split('/')

	if isinstance(opts.ip_af, types.StringTypes):
		opts.ip_af = {'4': socket.AF_INET, '6': socket.AF_INET6}[opts.ip_af]

	assert opts.packets > 0, opts.packets
	if ':' not in opts.send_delay:
		n, n_op = float(opts.send_delay), lambda n: n
	else:
		n, n_op = opts.send_delay.split(':', 1)
		try: n_op, args = n_op.split(':', 1)
		except ValueError: args = None
		n, n_op = float(n), getattr(op, n_op)
		if args: n_op = ft.partial(n_op, *map(float, args.split(':')))

	keys = dict()
	for k in opts.key:
		if k and k[0] in '/.':
			with open(k, 'rb') as src: k = src.read()
		for key in map(key_decode_signing, k.split()):
			key_id = key_get_id(key.verify_key)
			if key_id in keys:
				a, b = map(key_encode, [keys[key_id], key])
				raise ValueError('key_id ({}) conflict for keys: {}, {}'.format(key_id, a, b))
			else: keys[key_id] = key

	ts = time.time()
	for i in xrange(opts.packets):
		delay = time.time()
		dispatch_packets(
			opts.destination, opts.bind, keys, ts,
			family=opts.ip_af, random_addr=opts.random_addr )
		if i < opts.packets - 1:
			ts = time.time()
			delay = max(0, (delay + n) - ts)
			log.debug('Delay before sending next packet: %.2f', delay)
			n = n_op(n)
			time.sleep(delay)

if __name__ == '__main__': sys.exit(main())
