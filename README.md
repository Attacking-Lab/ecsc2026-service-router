# DSL Router

Authors:
 * hlt (Tobias Holl)
 * Diff-fusion (Felix Buchmann)

Categories:
 * rev
 * pwn
 * cry

## Overview

 * This is a Zephyr-based ADSL modem/router, shipped as (only) an Xtensa QEMU image.
 * The protocols spoken are mostly accurate (except the signalling layer):
    * The device connects to a (virtual) DSLAM via [ATM](https://en.wikipedia.org/wiki/Asynchronous_Transfer_Mode)
    * We implement a subset of the OAM F5 management protocol ([ITU-T I.610](https://www.itu.int/rec/T-REC-I.610-199902-I/en)) on top of the ATM layer for flag store 1.
    * Because ATM transports only fixed-size cells, we use AAL (ATM Adaption Layer) type 5 to fragment/reassemble larger payloads.
    * Over AAL5, there is a signalling layer that establishes and tears down ATM circuits. We use a custom signalling protocol, because the ITU standards (SSCOP, etc.) proved too complex for our use.
    * Higher-level data is also encapsulated in AAL5.
 * To emulate a 'real' ADSL modem, we carry some higher-level service over AAL5:
    * [PPPoEoA](https://en.wikipedia.org/wiki/Point-to-Point_Protocol_over_Ethernet#Use_with_DSL_%E2%80%93_PPPoE_over_ATM_(PPPoEoA)) is used to transport Ethernet frames
    * We decapsulate (but do not deal with fragmentation of) IP and UDP frames
    * Over UDP, you can talk to a CoAP (= "HTTP-over-UDP for IoT") server, which is flag store 2.
 * Because ATM is point-to-point, routing via different nodes requires establishing a circuit first.
   This is usually done synchronously on a single circuit (VPI 0, VCI 5), and we don't deviate from that.
   Because of this, the direct peer of the modem (DSLAM) needs to be trusted, or one team can trivially occupy all circuits.
   Therefore, we have a central DSLAM instance that manages this negotiation for us and enforces rate limits on the connecting teams.
 * The ATM-to-DSLAM connection is done via a custom vfio-user PCIe device (why the QEMU Xtensa board has PCIe support, I do not know).

### Flag Store 1

Flags are stored and retrieved via the system management OAM codes, which are implementation-delegated by I.610.
We expose two operations: `PUT` and `GET`.
`PUT` encrypts user data (the flag) and stores it to disk. It returns an ID (which becomes attack data) and the key used for encryption.
`GET` takes an ID and a nonce, then returns the ciphertext and `MAC(ciphertext || nonce, key)` (to prove that the service held on to the key).

### Flag Store 2

Flags are stored in the CoAP service, retrievable via their (public) ID and (private) handle/key.

## Vulnerabilities

### Flag Store 1, Vuln 1

 * Difficulty: easy
 * Discoverability: medium
 * Patchability: easy
 * Categories: rev, cry

The key generation for the flag store is purely uptime-seeded.
You can easily check all possible keys (there are at best 32 bits of entropy, and realistically in the duration of the CTF, roughly 24 bits of entropy).
Patching this _correctly_ is difficult (there's no good source of randomness on the device), but substituting some of the constants in the PRNG is generally sufficient.


### Flag Store 1, Vuln 2

 * Difficulty: easy
 * Discoverability: medium
 * Patchability: easy
 * Categories: rev, pwn

The code is carefully constructed so that the maximum valid nonce length in a packet can be two bytes longer than the buffer reserved for it.
An overlong nonce overwrites exactly the cipher suite of the entry that has been loaded from disk.
That entry consists of the secret key (the length of which is determined by the cipher suite), followed by the ciphertext.
This lets us set the ciphersuite to `F5CS_NULL`, which has a key length of zero, so the "ciphertext" that is returned is actually the key.


### Flag Store 2, Vuln 1

 * Difficulty: hard
 * Discoverability: hard
 * Patchability: medium
 * Categories: rev, pwn

Our implementation of AAL5 reassembly is flawed in a very subtle way.
When the trailer-indicated data length overlaps the trailer itself, that part of the trailer will overflow the end of the receive buffer.
This gives us limited control of what is written past the end of the buffer.
The overflow is

```
  uu:     u8
  cpi:    u8
  length: u16
  crc:    u32
```

with `uu` fully controllable and `crc` controllable by modifying the content (CRC is linear, of course).

This overflow hits a function pointer in userspace, which allows an attacker to pivot the stack into the request buffer and execute
arbitrary code. Because this is a _userspace_ buffer, not a kernel buffer, only one worker thread (with access only to flag store 2)
is compromised.

### Flag Store 2, Vuln 2

 * Difficulty: easy
 * Discoverability: medium
 * Patchability: medium
 * Categories: misc

The storage behind the CoAP flag store is really a FAT file name, i.e., a case-insensitive 8.3 identifier. The character _filter_ is
correct, but the case folding and other transformations (termination at bytes below 0x20, trailing dot stripping, etc.) is missing.
This means that creating an entry for any other key that maps to the same file leaks the flag.

### Flag Store 2, Vuln 3

 * Difficulty: easy
 * Discoverability: medium
 * Patchability: medium
 * Categories: misc

We pass the handle (read: password) for the CoAP storage entries via the `If-Match` option.
By the specification, if `If-Match` is _present but empty_, that matches _any_ representation
(read: password), so that just bypasses the authentication.

## Patches

All the patches are binary patches. For details, see `patches/`

## License

MIT License
