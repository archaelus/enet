
-record(raw, {data :: binary()
             }).

-type ethernet_address() :: list() | << _:48 >>.
-type ethertype() :: atom() | 0..65535.

-record(eth, {src :: ethernet_address()
              ,dst :: ethernet_address()
              ,type :: ethertype()
              ,data :: term()
             }).

-type ip_proto() :: atom() | 0..255.
-type ip_address() :: ipv4_address() | ipv6_addr().
-type ipv4_address() :: string() | << _:32 >> | 'localhost'.
-type arp_op() :: 'request' | 'reply' | 0..65535.
-type l3_proto() :: atom() | 0..65535.

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
               ,id = 0 :: integer()
               ,flags = <<0:3>> :: ipv4_flags()
               ,frag_offset = 0 :: non_neg_integer()
               ,ttl = 64 :: non_neg_integer()
               ,proto :: ip_proto()
               ,hdr_csum :: checksum()
               ,src :: ipv4_address()
               ,dst :: ipv4_address()
               ,options = [] :: list(ipv4_option()) | binary()
               ,data :: term()
              }).

-type port_no() :: 0..65535 | binary().
-type netport() :: list() | port_no().

-record(udp, {src_port :: port_no()
              ,dst_port :: port_no()
              ,length :: non_neg_integer()
              ,csum :: checksum()
              ,data :: term()
             }).

-type icmp_type() :: atom() | {Type::non_neg_integer(), Code::non_neg_integer()}.

-record(icmp, {type :: icmp_type()
               ,csum :: checksum()
               ,id :: non_neg_integer()
               ,seq :: non_neg_integer()
               ,data :: binary()
              }).

-type flag_value() :: boolean() | 0..1.

-type tcp_option() :: term().

-record(tcp, {src_port :: port_no()
              ,dst_port :: port_no()
              ,seq_no :: non_neg_integer()
              ,ack_no :: non_neg_integer()
              ,data_offset :: non_neg_integer()
              ,reserved :: non_neg_integer()
              ,urg :: flag_value()
              ,ack :: flag_value()
              ,psh :: flag_value()
              ,rst :: flag_value()
              ,syn :: flag_value()
              ,fin :: flag_value()
              ,window :: 0..65535
              ,csum :: checksum()
              ,urg_pointer :: non_neg_integer()
              ,options :: binary() | [tcp_option()]
              ,data :: term()
             }).

-type af_type() :: atom() | 0..255.

-record(null, {type :: af_type(),
               data :: term()}).

-type ipv6_addr() :: localhost | << _:128 >>.

-record(ipv6, {version = 6,
               traffic_class :: non_neg_integer(),
               flow_label :: bitstring(),
               payload_len :: non_neg_integer(),
               next_hdr :: ip_proto(),
               hop_count = 255 :: 0..255,
               src :: ipv6_addr(),
               dst :: ipv6_addr(),
               payload :: term()}).

-record(ipv6_frag, {offset,
                    m,
                    id}).

-record(ipv6_route, {type, segments, addresses}).

-record(ip_pseudo_hdr, {src :: << _ : 32 >> | << _:128 >>
                       ,dst :: << _ : 32 >> | << _:128 >>
                       ,proto :: 0..255
                       }).
