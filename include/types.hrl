
-record(eth, {src,dst,type,data}).

-record(arp, {htype, ptype,
              haddrlen, paddrlen,
              op,
              sender, target}).

-record(ipv4, {vsn,
               hlen,
               diffserv,
               totlen,
               id,
               flags,
               frag_offset,
               ttl,
               proto,
               hdr_csum,
               src,dst,
               options,
               data}).

-record(ipv4_opt, {type, copy, data}).

-record(udp, {src_port, dst_port, length, csum, data}).
