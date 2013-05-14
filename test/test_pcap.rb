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
    
  end
end
