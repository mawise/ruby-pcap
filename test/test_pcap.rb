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
  end
end
