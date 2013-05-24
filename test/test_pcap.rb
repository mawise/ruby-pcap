require 'test/unit'
require 'pcaplet'

def get_packet(filename)
  capture = Pcap::Capture.open_offline("test/#{filename}")
  packets = []
  capture.each_packet do |pkt|
    packets.push(pkt)
  end
  packets.first
end

class PcapTest < Test::Unit::TestCase
  def test_ip_addr_marshall
    p = get_packet("ipv4-tcp-http.pcap")
    addr = p.src
    assert addr.is_a? Pcap::IPAddress
    dumped = Marshal.dump(addr)
    loaded = Marshal.load(dumped)
    
    assert loaded.is_a? Pcap::IPAddress
    assert_equal addr, loaded
    assert_equal addr.to_s, loaded.to_s
  end

  def test_ip_tcp_packet
    p = get_packet("ipv4-tcp-http.pcap")
    assert p.ip?
    assert p.tcp?
    assert_equal "145.254.160.237", p.ip_src.to_s
    assert_equal "145.254.160.237", p.src.to_s
    assert_equal "65.208.228.223", p.ip_dst.to_s
    assert_equal "65.208.228.223", p.dst.to_s
    assert_equal 4, p.ip_ver
    assert_equal 5, p.ip_hlen
    assert_equal 0, p.ip_tos
    assert_equal 3909, p.ip_id
    assert_equal 2, p.ip_flags
    assert p.ip_df?
    assert !p.ip_mf?
    assert_equal 6, p.ip_proto # TCP

    assert_equal 3372, p.tcp_sport
    assert_equal 3372, p.sport
    assert_equal 80, p.tcp_dport
    assert_equal 80, p.dport
    assert_equal 290218380, p.tcp_ack, "tcp_ack"
    assert_equal 951057940, p.tcp_seq, "tcp_seq"
    assert_equal 24, p.tcp_flags
    assert !p.tcp_fin?
    assert !p.tcp_syn?
    assert !p.tcp_rst?
    assert p.tcp_psh?
    assert p.tcp_ack?
    assert !p.tcp_urg?
    assert_equal 5, p.tcp_hlen, "tcp_hlen"
    assert_equal 5, p.tcp_off, "tcp_off"
    assert_equal 0xa958, p.tcp_sum
    assert_equal 9660, p.tcp_win
  end

  def test_ip_udp_packet
    p = get_packet("ipv4-udp-dns.pcap")
    assert p.ip?
    assert p.udp?
    assert_equal 3009, p.udp_sport
    assert_equal 3009, p.sport
    assert_equal 53, p.udp_dport
    assert_equal 53, p.dport
    assert_equal 55, p.udp_len
  end

  def test_ip6_addr
    p = get_packet("ipv6-tcp-ssh.pcap")
    assert p.ip6?
    addr = p.ip6_src
    assert addr.is_a? Pcap::IP6Address
    dumped = Marshal.dump(addr)
####  The Marshaling for Pcap::IP6Address is broken.  TODO: Fix it.  
  #  loaded = Marshal.load(dumped)
  #  assert loaded.is_a? Pcap::IP6Address "Marshaled and loaded ip6 address should be an ip6 address"
  #  assert_equal addr, loaded, "Marshaled and loaded ip6 objects should be the same"
  #  assert_equal addr.to_s, loaded.to_s, "Marshaled and loaded ip6 objects should have the same string format"
  end

  def test_ip6_icmp6_echoreply
    p = get_packet("ipv6-icmpv6-echoreply.pcap")
    assert p.ip6?
    assert_equal "Pcap::IP6Address", p.ip6_src.class.to_s
    assert_equal "Pcap::IP6Address", p.ip6_dst.class.to_s
    assert_equal "3ffe:507:0:1:260:97ff:fe07:69ea", p.ip6_src.to_s
    assert_equal "3ffe:507:0:1:200:86ff:fe05:80da", p.ip6_dst.to_s
    assert_equal 0x3ffe0507, p.ip6_src.to_a[0]
    assert_equal 0x00000001, p.ip6_src.to_a[1]
    assert_equal 0x026097ff, p.ip6_src.to_a[2]
    assert_equal 0xfe0769ea, p.ip6_src.to_a[3]
    assert_equal 0x3ffe, p.ip6_dst.to_a16[0]
    assert_equal 0x0507, p.ip6_dst.to_a16[1]
    assert_equal 0x80da, p.ip6_dst.to_a16[7]
    assert p.is_a?(Pcap::ICMP6Packet), "it should be an ICMP6Packet"
    assert p.is_a?(Pcap::ICMP6EchoPacket), "it should be an ICMP6EchoPacket"
    assert p.icmp6?
    assert_equal Pcap::ICMP6_ECHO_REPLY, p.icmp6_type
    assert_equal 0, p.icmp6_code
    assert_equal 0x5a80, p.icmp6_cksum
    assert_equal 0x7b20, p.icmp6_id
    assert_equal 768, p.icmp6_seq
  end

  def test_ip6_icmp_err
    p = get_packet("ipv6-icmpv6-err-timeexceeded.pcap")
    assert p.ip6?
    assert p.icmp6?
    assert p.is_a? Pcap::ICMP6ErrorPacket
    assert_equal Pcap::ICMP6_TIME_EXCEEDED, p.icmp6_type
    assert_equal 0, p.icmp6_code, "Code should be corrent"
    assert_equal 0xbe64, p.icmp6_cksum, "Checksum should be corect"
    assert p.icmp6_pkt.is_a?(Pcap::Packet), "should contain a Packet"
    assert p.icmp6_pkt.ip6?, "should contain an IPv6 Packet" 
  end
  
  def test_ip6_tcp
    p = get_packet("ipv6-tcp-ssh.pcap")
    assert p.ip6?
    assert p.tcp?, "should be a tcp packet"
    assert_equal 1022, p.tcp_sport
    assert_equal 1022, p.sport
    assert_equal 22, p.tcp_dport
    assert_equal 22, p.dport
    assert !p.tcp_urg?
    assert p.tcp_ack?
    assert p.tcp_psh?
    assert !p.tcp_rst?
    assert !p.tcp_syn?
    assert !p.tcp_fin?
    assert_equal 8, p.tcp_hlen, "TCP Header Length"
    assert_equal 0xaa57, p.tcp_sum, "TCP Checksum"
    assert_equal 8520, p.tcp_win, "TCP Window Size"
  end

  def test_ip6_udp
    p = get_packet("ipv6-udp-dns.pcap")
    assert p.ip6?
    assert p.udp?
  end
end
