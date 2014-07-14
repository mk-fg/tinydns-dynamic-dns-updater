tinydns-dynamic-dns-updater
--------------------

Tool to generate and keep [tinydns](http://tinydns.org/)
(resolver daemon from [djbdns](http://cr.yp.to/djbdns.html))
zone file with dynamic dns entries for remote hosts.

It consists of "client" part sending (several) UDP packets with public key id
and signed current timestamp to "server", which matches key to a name that
should be updated and makes sure timestamp is newer than that of the last update
there, and if so, uses source address of the packet to update djbdns database
name-ip binding.

All configuration for server is contained within djbdns zone file itself, client
only needs commandline parameters for server and path to the client key.

This approach differs from solutions for same task I've seen in that it doesn't
involve php, http server, passwords or similar stuff, but requires running
simple python scripts on both client and server instead.

Or that's the plan, at least.
Everything is under development, nothing works yet.



Operation details
--------------------

 * Client doesn't get any confirmation and is expected to just send as much
   redundant data (and as often), as required by tolerance for stale data and
   network reliability.

 * It makes sense (and is safe) to send any number of UDP update packets,
   server-side old ones and non-changes are ignored.

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
