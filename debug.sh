#!/bin/bash

exec erl -pa ebin -boot start_sasl -eval '{ok, Pid} = enet_iface:start("tap0", "192.168.2.1/24 up"), enet_if_dump:attach(Pid), enet_if_arp:attach(Pid), enet_if_arp:add_entry(Pid, "4A:6E:01:1B:19:8F", "192.168.2.2"), enet_if_icmp:attach(Pid), enet_if_crtest:attach(Pid, "priv/breakage").'
