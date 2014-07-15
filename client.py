#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import os, sys, socket, struct, time

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

def get_socket_info( host, port=0, family=0,
		socktype=0, protocol=0, force_unique_address=False ):
	log_params = [port, family, socktype, protocol]
	log.debug('Resolving addr: %r (params: %s)', host, log_params)
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

	if len(ai_af) > 1:
		af_names = dict((v, k) for k,v in vars(socket).viewitems() if k.startswith('AF_'))
		ai_af_names = list(af_names.get(af, str(af)) for af in ai_af)
		if socket.AF_INET not in ai_af:
			log.fatal(
				'Ambiguous socket host specification (matches address famlies: %s),'
					' refusing to pick one at random - specify socket family instead. Addresses: %s',
				', '.join(ai_af_names), ', '.join(ai_addr) )
			raise AddressError
		log.warn( 'Specified host matches more than'
			' one address family (%s), using it as IPv4 (AF_INET)', ai_af_names )
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


def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='Tool to update tinydns zone file entries for host remotely.')

	parser.add_argument('destination', nargs='?',
		help='Address/port to of the remote listening udp socket'
			' to send update information to, in "host[:port]" format'
			' (where port defaults to {}, if omitted).'.format(default_port))

	parser.add_argument('key', nargs='*',
		help='Ed25519 signing key or absoulte path to a file'
				' with one or more (separated by spaces/newlines) keys to use for client id.'
			' Can be specified multiple times to use multiple keys/files'
				' at the same time, sending one update to dst host for each key.'
			' --genkey option can be used to generate signing/verify keypairs suitable'
				' for use on destination host (only verify key is needed there) and with this'
				' script (signing key).')

	# XXX: option to send N time-spaced updates

	parser.add_argument('-g', '--genkey', action='store_true',
		help='Generate a new random signing/verify'
			' Ed25519 keypair, print both keys to stdout and exit.')

	parser.add_argument('-b', '--bind', metavar='[host:]port',
		help='Host/port to bind sending socket to.'
			' Can be useful for firewall rules and to explicitly bind to external interface.'
			' Example: 1.2.3.4:8793')

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

	if not opts.destination: parser.error('Destination endpoint must be specified')
	if not opts.key: parser.error('At least one key must be specified')

	try: host, port = opts.destination.rsplit(':', 1)
	except ValueError: host, port = opts.destination, default_port
	dst_socktype, dst_port = socket.SOCK_DGRAM, int(port)
	dst_af, dst_addr = get_socket_info( host,
		dst_port, socktype=dst_socktype, force_unique_address=True )

	bind = False
	if opts.bind:
		bind = True
		try: host, port = opts.bind.rsplit(':', 1)
		except ValueError:
			parser.error('--bind argument must be in "host:port" format')
		else:
			bind_socktype, bind_port = socket.SOCK_DGRAM, int(port)
			bind_af, bind_addr = get_socket_info( host,
				bind_port, socktype=bind_socktype, force_unique_address=True )

	keys = dict()
	for k in opts.key:
		if k.startswith(os.sep):
			with open(k, 'rb') as src: k = src.read()
		for key in map(key_decode_signing, k.split()):
			key_id = key_get_id(key.verify_key)
			if key_id in keys:
				a, b = map(key_encode, [keys[key_id], key])
				raise ValueError('key_id ({}) conflict for keys: {}, {}'.format(key_id, a, b))
			else: keys[key_id] = key

	ts = time.time()
	msgs = list(build_msg(key, ts, key_id) for key_id, key in keys.viewitems())

	log.debug( 'Sending %s update msg(s) to: %r (port: %s,'
		' af: %s, socktype: %s)', len(msgs), dst_addr, dst_port, dst_af, dst_socktype )
	sock = socket.socket(dst_af, dst_socktype)
	if bind:
		assert bind_af == dst_af and bind_socktype == dst_socktype,\
			[bind_af, dst_af, bind_socktype, dst_socktype]
		log.debug('Binding sending socket to: %r (port: %s)', bind_addr, bind_port)
		sock.bind((bind_addr, bind_port))
	for msg in msgs:
		sock.sendto(msg, (dst_addr, dst_port))

if __name__ == '__main__': sys.exit(main())
