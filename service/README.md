# router

I really wanted to put [wet string](https://www.revk.uk/2017/12/its-official-adsl-works-over-wet-string.html) all over the venue, but I was overruled.
Still, this is some play on an ADSL router.
Everything that is relevant is within the firmware itself.
The network device code does not contain any (intentional, at least) vulnerabilities, you should consider it out-of-scope.

You can find the numbers you need to dial for each team in the [numbering plan](http://dslam/numbering-plan.yaml).
We won't change the numbering plan without a corresponding announcement, feel free to cache it.

**Important**: This service uses a single outbound connection to the DSLAM for all communication.
To make sure other services can't break this connection, the only way to reach the DSLAM from your vulnbox is from the service container itself.
This is enforced by routing all traffic to the DSLAM via bogon IPs and filtering it with nftables.
Keep this in mind if you modify nftables rules.

---

You may find more details in the relevant standards:

- [ITU-T I.361](https://www.itu.int/rec/T-REC-I.361/en) (*B-ISDN ATM layer specification*)
- [ITU-T I.432.1](https://www.itu.int/rec/T-REC-I.432.1/en) (*B-ISDN user-network interface - Physical layer specification: General characteristics*)
- [ITU-T I.363.5](https://www.itu.int/rec/T-REC-I.363.5/en) (*B-ISDN ATM Adaptation Layer specification: Type 5 AAL*)
- [ITU-T I.610](https://www.itu.int/rec/T-REC-I.610-199902-I/en) (*B-ISDN operation and maintenance principles and functions*)
- [ITU-T E.191](https://www.itu.int/rec/T-REC-E.191/en) (*B-ISDN addressing*)
- [ITU-T E.164](https://www.itu.int/rec/T-REC-E.164/en) (*International public telecommunication numbering plan*)
- [RFC 2684](https://www.rfc-editor.org/rfc/rfc2684) (*Multiprotocol Encapsulation over ATM Adaptation Layer 5*)
- [RFC 2516](https://www.rfc-editor.org/rfc/rfc2516) (*A Method for Transmitting PPP Over Ethernet (PPPoE)*)
- [RFC 1661](https://www.rfc-editor.org/rfc/rfc1661) (*The Point-to-Point Protocol (PPP)*)
- [RFC 791](https://www.rfc-editor.org/rfc/rfc791) (*Internet Protocol*)
- [RFC 768](https://www.rfc-editor.org/rfc/rfc768) (*User Datagram Protocol*)
- [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252) (*The Constrained Application Protocol (CoAP)*)
- [RFC 6690](https://www.rfc-editor.org/rfc/rfc6690) (*Constrained RESTful Environments (CoRE) Link Format*)

We do not implement an _actual_ physical layer (and no DOCSIS either), nor do we have standards-compliant signalling. The real thing, [Q.2931](https://www.itu.int/rec/T-REC-Q.2931/en) over SSCF ([Q.2130](https://www.itu.int/rec/T-REC-Q.2130/en)) and SSCOP ([Q.2110](https://www.itu.int/rec/T-REC-Q.2110/en)), would have been a bit too far. At the top end of the protocol stack, we opted for a (simpler) CoAP implementation over the usual TR-069 (which needs a full TCP stack and XML parsing).

Many of the other standards are only implemented as far as necessary to make this service work.
We probably also unintentionally deviated from the standards in some places.
Thankfully, this network is self-contained, don't expect it to interoperate with your home router.

You can run the example client by running `python -m patmy`.
A (much!) simplified version of the DSLAM for local testing can be found in `mindslam/`

---

To ensure network stability, we impose a few limits.
No team is able to open more than **32** connections to the DSLAM at the same time, nor may it open more than **four** circuits to the same destination at the same time.
Connections past that limit are closed immediately, circuits past the limit are refused with `QUOTA_EXCEEDED`.
Circuits are automatically closed after 180 seconds, but please close them yourself to avoid them counting against your limits.
