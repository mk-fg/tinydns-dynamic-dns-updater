#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from contextlib import contextmanager, closing
from collections import namedtuple, defaultdict
from tempfile import NamedTemporaryFile
import os, sys, re, socket, struct, fcntl

import nacl, netaddr


key_id_len = 10 # XXX: real value here
sig_len = 10 # XXX: real value here
msg_fmt = '!{}sd{}s'.format(key_id_len, sig_len)
msg_len = struct.calcsize(msg_fmt)
msg_data_len = msg_len - sig_len


class AddressError(Exception): pass

def get_socket_info( host, port=0, family=0,
		socktype=0, protocol=0, force_unique_address=False ):
	log_params = [port, family, socktype, protocol]
	log.debug('Resolving addr: {!r} (params: {})'.format(host, log_params))
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
				( 'Ambiguous socket host specification (matches address famlies: {}),'
					' refusing to pick one at random - specify socket family instead. Addresses: {}' )
				.format(', '.join(ai_af_names), ', '.join(ai_addr)) )
			raise AddressError
		log.warn( 'Specified host matches more than'
			' one address family ({}), using it as IPv4 (AF_INET).'.format(ai_af_names) )
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
			' one address ({}), using first one: {}'.format(ai_addr_unique, addr) )

	return af, addr

def it_ngrams(seq, n):
	z = (it.islice(seq, i, None) for i in range(n))
	return zip(*z)

@contextmanager
def safe_replacement(path):
	kws = dict( delete=False,
		dir=os.path.dirname(path), prefix=os.path.basename(path)+'.' )
	with NamedTemporaryFile(**kws) as tmp:
		try:
			yield tmp
			tmp.flush()
			os.rename(tmp.name, path)
		finally:
			try: os.unlink(tmp.name)
			except (OSError, IOError): pass

def with_src_lock(shared=False):
	lock = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
	def _decorator(func):
		@ft.wraps(func)
		def _wrapper(src, *args, **kws):
			fcntl.lockf(src, lock)
			try: return func(src, *args, **kws)
			finally:
				try: fcntl.lockf(src, fcntl.LOCK_UN)
				except (OSError, IOError) as err:
					log.exception('Failed to unlock file object: %s', err)
		return _wrapper
	return _decorator


def key_decode(key_raw):
	return key.decode('base64') # XXX: not necessary if pynacl has some repr

def key_get_id(key):
	return key # XXX: some hash of it, same as client sends

def key_check_sig(key, pkt):
	return True # XXX: real check op


def zone_addr_format(addr):
	if addr.version == 4: return addr.format()
	else: return ''.join('{:04x}'.format(n) for n in addr.words())

@with_src_lock(shared=True)
def zone_parse(src):
	block, bol_next, entries = None, 0, defaultdict(list)
	src_ts = os.fstat(src.fileno()).st_mtime

	src.seek(0)
	for line in iter(src.readline, ''):
		bol, bol_next = bol_next, src.tell()
		line = line.strip()

		if line.startswith('#'):
			match = re.search(r'\s*dynamic:\s*((\d+(\.\d+)?)\s.*)$', line[1:])
			if match:
				data, ts_span = match.group(1).split(), match.span(2)
				keys = map(key_decode, data[1:])
				key_ids = map(key_get_id, keys)
				block = dict(
					ts=float(data[0]), ts_span=ts_span,
					line=' '.join(data), keys=dict(zip(key_ids, keys)), names=list() )
				for key_id in key_ids: entries[key_id].append(block)
				continue
			line = ''

		if not line: block = None
		if not block: continue

		if line[0] in '+6':
			name, addr_raw = line[1:].split(':', 2)
			addr, ver = addr_raw, None
			if line[0] == '6': ver, addr = 6, ':'.join(''.join(v) for v in it_ngrams(addr, 4))
			elif line[0] == '+': ver = 4
			else: raise NotImplementedError()
			block['names'].append(dict(
				name=name, bol=bol,
				addr_raw=addr_raw, addr=netaddr.IPAddress(addr) ))

	return src_ts, entries

ZoneUpdateAddr = namedtuple('ZoneUpdateAddr', 'pos entry addr')
ZoneUpdateTime = namedtuple('ZoneUpdateTime', 'pos block ts')

class InvalidPacket(Exception): pass

@with_src_lock(shared=False)
def zone_update(src, src_ts, updates):
	src.seek(0)
	res, src_buff = res, memoryview(src.read())

	pos, pos_used = None, set()
	updates.sort(reverse=True) # last update pos first
	for u in updates:
		if isinstance(u, ZoneUpdateAddr):
			log.debug( 'Updating zone entry for name'
				' %r: %s -> %s', u.entry['name'], u.entry['addr'], u.addr )
			a = u.entry['bol']
			b = src_buff.find('\n', a)
			res.append(src_buff[b:pos])
			res.append(re.sub(
				r'(?<=:){}((?=[:\s])|$)'.format(re.escape(u.entry['addr_raw'])),
				zone_addr_format(u.addr), src_buff[a:b] ))
		elif isinstance(u, ZoneUpdateTime):
			log.debug('Updating zone block %r ts: %.2f -> %.2f', u.entry['line'], u.entry['ts'], u.ts)
			a, b = u.entry['ts_span']
			res.append(src_buff[b:pos])
			res.append('{.2f}'.format(u.ts))
		else: raise ValueError(u)
		pos = b
		assert pos not in pos_used, pos
		pos_used.add(pos)
	res.append(src_buff[:pos])

	res = ''.join(reversed(res))
	del src_buff
	src_stat = lambda: os.fstat(src.fileno()).st_mtime
	with safe_replacement(src.name) as tmp:
		tmp.write(res)
		assert abs(src_stat() - src_ts) < 1
		# For things that already have old file opened
		src.seek(0)
		src.truncate()
		src.write(res)
		assert abs(src_stat() - src_ts) < 1

def zone_update_loop(src_path, sock):
	with open(src_path, 'rb') as src:
		src_ts, entries = zone_parse(src)

	while True:
		pkt, ep = sock.recvfrom(65535)

		try:
			if len(pkt) != msg_len:
				raise InvalidPacket('size mismatch (must be %s): %s', len(pkt), msg_len)
			key_id, ts, sig = struct.unpack(msg_fmt, pkt)
			blocks = entries.get(key_id)
			if not blocks: raise InvalidPacket('unrecognized key id: %s', key_id)
			blocks = filter(lambda b: b['ts'] < ts, blocks)
			if not blocks:
				raise InvalidPacket('repeated/old ts (current: %s): %s', entry['ts'], ts)
			key, msg_data = blocks[0]['keys'][key_id], pkt[:msg_data_len]
			if not key_check_sig(key, msg_data):
				raise InvalidPacket('signature check failed (key: %r): %r', key, msg_data)
		except InvalidPacket as err:
			log.debug('Invalid packet - ' + err.args[0], *err.args[1:])
			continue

		addr_raw, port = ep[:2]
		addr = netaddr(addr_raw)
		updates = list()
		for block in blocks:
			for entry in block['names']:
				if entry['addr'] != addr:
					updates.append(ZoneUpdateAddr(entry['bol'], entry, addr))
			updates.append(ZoneUpdateTime(block['ts_span'][0], block, ts))
		if not updates:
			log.debug( 'No changes in valid update'
				' packet: key_id=%s ts=%.2f addr=%s', key_id, ts, addr )
		else:
			with open(src_path, 'a+') as src: zone_update(src, updates)


def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='Tool to generate and keep tinydns'
			' zone file with dynamic dns entries for remote hosts.')

	parser.add_argument('zone_file',
		help='Path to tinydns zone file with client Ed25519 (base64-encoded)'
				' pubkeys and timestamps in comments before entries.'
			' Basically any line with IPs that has comment in the form of'
				' "dynamic: <ts> <pubkey> <pubkey2> ..." immediately before it (no empty lines'
				' or other comments separating these) can be updated by packet with'
				' proper ts/signature.')

	parser.add_argument('-b', '--bind',
		metavar='[addr:]port', default='5533',
		help='Address/port to bind listening socket to (default: %(default)s).')

	parser.add_argument('-d', '--debug', action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	import logging
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = logging.getLogger()

	try: host, port = opts.bind.rsplit(':', 1)
	except ValueError: host, port = '::', opts.bind
	socktype, port = socket.SOCK_DGRAM, int(port)
	af, addr = get_socket_info(host, port, socktype=socktype, force_unique_address=True)

	# XXX: receive socket from systemd
	log.debug('Binding to: {!r} (port: {}, af: {}, socktype: {})'.format(addr, port, af, socktype))
	sock = socket.socket(af, socktype)
	sock.bind((addr, port))
	# XXX: drop uid/gid here

	with open(opts.zone_file, 'rb'): pass # access check
	zone_update_loop(opts.zone_file, sock)

if __name__ == '__main__': sys.exit(main())
