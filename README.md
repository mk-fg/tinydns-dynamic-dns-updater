tinydns-dynamic-dns-updater
--------------------

Tool to generate and keep [tinydns](http://tinydns.org/)
(resolver daemon from [djbdns](http://cr.yp.to/djbdns.html))
zone file with dynamic dns entries for remote hosts.

It consists of "client" part that sends (several) UDP packets with signing key
id and signed current timestamp to "server", which matches key to a name that
should be updated and makes sure timestamp is newer than that of the last update
there, and if so, uses source address of the packet to update djbdns database
name-ip binding.

All configuration for server is contained within djbdns zone file itself, client
only needs commandline parameters for server and path to the client key.

This approach differs from solutions for same task I've seen in that it doesn't
involve php, http server, passwords (usually passed in plaintext over net), tls
or similar stuff, but requires running simple python scripts on both client and
server instead.



Usage
--------------------

Example ("S" is for server terminal, "C" - client):

```
S% ./tddu-client.py -g

S: Signing key (for this script only):
S:    1k_Nf7FSEWHC2I65DfI2SAhtk1q0Ps9RcLy9PinyDLs=
S:
S: Verify key (to use on server):
S:    jLxAZY-vnJfubHr8srYy3mIN2_mCi_OExUwHOluOlLY=
S:

[...these keys are used in zone_file.example and with tddu-client.py...]

S% cat zone_file.example

S: +some.static.name:213.180.193.3
S:
S: # dynamic: 0 jLxAZY-vnJfubHr8srYy3mIN2_mCi_OExUwHOluOlLY=
S: +some.random.name:37.98.242.143
S: +extra.random.name:37.98.242.143
S: 6some.random.name:2a00145040100c080000000000000066
S:
S: +another.static.name:93.158.134.3
S: 6another.static.name:2a0206b8000000000000000000000003

S% cp zone_file.example zone_file.example.tmp && ./tddu-server.py --debug zone_file.example.tmp

S: DEBUG:root:Resolving addr: '::' (params: [5533, 0, 2, 0])
S: DEBUG:root:Binding to: '::' (port: 5533, af: 10, socktype: 2)

C% ./tddu-client.py --debug ::1:5533 1k_Nf7FSEWHC2I65DfI2SAhtk1q0Ps9RcLy9PinyDLs=

C: DEBUG:root:Resolving addr: '::1' (params: [5533, 0, 2, 0])
C: DEBUG:root:Sending 1 update msg(s) to: '::1' (port: 5533, af: 10, socktype: 2)

S: DEBUG:root:Updating zone entry for name 'some.random.name' (type: 6): 2a00:1450:4010:c08::66 -> ::1
S: DEBUG:root:Updating zone block '0 jLxAZY-vnJfubHr8srYy3mIN2_mCi_OExUwHOluOlLY=' ts: 0.00 -> 1405421249.89

[...it's a BAD idea to pass keys on cli like that, so store it to "./client.key" file...]

C% ./tddu-client.py --debug 127.0.0.1:5533 ./client.key

C: DEBUG:root:Resolving addr: '127.0.0.1' (params: [5533, 0, 2, 0])
C: DEBUG:root:Sending 1 update msg(s) to: '127.0.0.1' (port: 5533, af: 2, socktype: 2)

S: DEBUG:root:Updating zone entry for name 'extra.random.name' (type: +): 37.98.242.143 -> 127.0.0.1
S: DEBUG:root:Updating zone entry for name 'some.random.name' (type: +): 37.98.242.143 -> 127.0.0.1
S: DEBUG:root:Updating zone block '1405421249.89 jLxAZY-vnJfubHr8srYy3mIN2_mCi_OExUwHOluOlLY=' ts: 1405421249.89 -> 1405421540.03

C% ./tddu-client.py 127.0.0.1:5533 ./client.key

S: DEBUG:root:No address changes in valid update packet: key_id=QlH0RDCxXrI2OvL2OUA4DBeDY79X ts=1405423510.34 addr=127.0.0.1
```


### Requirements

 * Python 2.7 (not 3.X)

 * [PyNaCl](http://pynacl.readthedocs.org/)

 * [netaddr](https://github.com/drkjam/netaddr/)

 * (optional)
   [python-systemd](http://www.freedesktop.org/software/systemd/python-systemd/)
   - to use systemd socket activation for server (--systemd option).



Operation details
--------------------

 * Payload of sent UDP packets is fixed 100 bytes in size.

   28B key_id (pubkey hash) || 8B timestamp (double) || 64B Ed25519 signature.

 * Client doesn't get any confirmation and is expected to just send as much
   redundant data (and as often), as required by tolerance for stale data and
   network reliability.

 * It makes sense (and is safe) to send any number of UDP update packets, old
   ones and non-changes are ignored server-side, as well as any otherwise
   invalid packets in general.

 * Since address is determined from UDP packet source, it matter whether it gets
   sent over IPv4 or IPv6, and whether there's any SNAT translation in-between.

 * If hostname is passed anywhere instead of address, it is resolved by
   getaddrinfo(3), and if there are several different results, error is raised
   to prevent ambiguity, esp. wrt IPv4/IPv6 resolution (see also
   `/etc/gai.conf`).

 * Signatures are used as a simple means of client id and
   authentication.

   [Ed25519 public-key signature system](http://ed25519.cr.yp.to/)
   (as implemented in [PyNaCl](http://pynacl.readthedocs.org/) module)
   is used.

 * Timestamps are sent to discard obsolete updates and replay attacks.

   They are not considered to be worth hiding, and are cheaper to check on
   server before validating signature when sent in plaintext.



Links
--------------------

 * [tinydns (non-commercial) promotion/community page](http://tinydns.org/)

 * [djb's cr.yp.to page for djbdns](http://cr.yp.to/djbdns.html)

 * [Ed25519 public-key signature system info](http://ed25519.cr.yp.to/)



TODO
--------------------

 * Run cdb rebuild or any optional hook script after updates on server.
