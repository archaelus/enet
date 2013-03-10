-record(entry, {ethaddr :: enet_eth:address(),
                ipaddr :: enet_ipv4:address(),
                publish = false :: boolean(),
                expiry :: erlang:timestamp()}).
