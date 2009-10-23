
-record(eth, {src,dst,type,data}).

-record(arp, {op,
              htype, ptype,
              haddrlen, paddrlen,
              sender, target}).
