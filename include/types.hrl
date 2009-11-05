
-type ethernet_address() :: list() | << _:48 >>.
-type ethertype() :: atom() | non_neg_integer().

-record(eth, {src :: ethernet_address()
              ,dst :: ethernet_address()
              ,type :: ethertype()
              ,data :: term()
             }).

-type ipv4_proto() :: atom() | non_neg_integer().
-type ipv4_address() :: list() | << _:32 >>.
-type arp_op() :: 'request' | 'reply' | non_neg_integer().
-type l3_proto() :: atom() | non_neg_integer().

-record(arp, {htype :: ethertype()
              ,ptype :: l3_proto()
              ,haddrlen :: non_neg_integer()
              ,paddrlen :: non_neg_integer()
              ,op :: arp_op()
              ,sender :: {ethernet_address(), ipv4_address()}
              ,target :: {ethernet_address(), ipv4_address()}
             }).

-type checksum() :: 'correct' | {'incorrect', integer()} | integer().

-record(ipv4_opt, {type :: atom() | {non_neg_integer(), non_neg_integer()}
                   ,copy :: 1 | 0
                   ,data :: term()
                  }).

-type ipv4_flag() :: 'evil' | 'dont_fragment' | 'more_fragments'.
-type ipv4_flags() :: << _:3 >> | list(ipv4_flag()).
-type ipv4_option() :: #ipv4_opt{}.

-record(ipv4, {vsn = 4 :: integer()
               ,hlen :: non_neg_integer()
               ,diffserv = 0 :: integer()
               ,totlen :: non_neg_integer()
               ,id :: integer()
               ,flags :: ipv4_flags()
               ,frag_offset = 0 :: non_neg_integer()
               ,ttl = 64 :: non_neg_integer()
               ,proto :: ipv4_proto()
               ,hdr_csum :: checksum()
               ,src :: ipv4_address()
               ,dst :: ipv4_address()
               ,options :: list(ipv4_option()) | binary()
               ,data :: term()
              }).


-record(udp, {src_port :: 0..65535
              ,dst_port :: 0..65535
              ,length :: non_neg_integer()
              ,csum :: checksum()
              ,data :: term()
             }).

-type icmp_type() :: atom() | non_neg_integer().

-record(icmp, {type :: icmp_type()
               ,csum :: checksum()
               ,id :: non_neg_integer()
               ,seq :: non_neg_integer()
               ,data :: binary()
              }).
