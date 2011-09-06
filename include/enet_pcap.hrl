-define(PCAP_MAGIC, <<16#d4,16#c3,16#b2,16#a1>>).
-define(PCAP_HDR_SIZE, 24). % 4+2+2+4+4+4+4
-define(PCAP_PKTHDR_SIZE, 16). % 4+4+4+4
-record(pcap_hdr, {version
                   ,tz_correction
                   ,sigfigures
                   ,snaplen
                   ,datalinktype
                   ,endianness :: 'little' | 'big'
                  }).
-record(pcap_pkt, {ts :: {S::non_neg_integer(),
                          US::non_neg_integer()},
                   orig_len :: non_neg_integer(),
                   data :: binary()}).
