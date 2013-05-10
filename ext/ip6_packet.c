/*
 *  ip6_packet.c
 *
 *  $Id: ip6_packet.c,v 1.1.1.1 2013/05/09 21:00:00 wise Exp $
 *  Copyright (C) 1998, 1999  Masaki Fukushima
 */

#include "ruby_pcap.h"
#include <netdb.h>

VALUE cIP6Packet;

#define CheckTruncateIp6(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer3_off, need, "truncated IP6")

#define IPV6_VERSION_MASK 0xf0
#define IPV6_FLOWLABEL_MASK 0x000fffff
#define IPV6_TRAFFICCLASS_MASK 0x0ff00000

VALUE
setup_ip6_packet(pkt, nl_len)
     struct packet_object *pkt;
     int nl_len;
{
    VALUE class;

    DEBUG_PRINT("setup_ip6_packet");

    if (nl_len > 0 && IP_HDR(pkt)->ip_v != 6) {
        return cPacket;
    }

    class = cIP6Packet;

    return class;
}

#define IP6P_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
     struct packet_object *pkt;\
     struct ip6_hdr *ip6;\
\
     DEBUG_PRINT(#func);\
     GetPacket(self, pkt);\
     CheckTruncateIp6(pkt, (need));\
     ip6 = IP6_HDR(pkt);\
     return (val);\
}


IP6P_METHOD(ip6p_ver,    1,  INT2FIX((ip6->ip6_vfc & IPV6_VERSION_MASK)>>4))
IP6P_METHOD(ip6p_tclass, 4,  INT2FIX((ntohl(ip6->ip6_flow) & IPV6_TRAFFICCLASS_MASK)>>20))
IP6P_METHOD(ip6p_flow,   4,  INT2FIX(ntohl(ip6->ip6_flow) & IPV6_FLOWLABEL_MASK))
IP6P_METHOD(ip6p_plen,   6,  INT2FIX(ntohs(ip6->ip6_plen)))
IP6P_METHOD(ip6p_nxt,    7,  INT2FIX(ip6->ip6_nxt))
IP6P_METHOD(ip6p_hlim,   8,  INT2FIX(ip6->ip6_hlim))


void
Init_ip6_packet(void)
{
    DEBUG_PRINT("Init_ip6_packet");

    cIP6Packet = rb_define_class_under(mPcap, "IP6Packet", cPacket);
    
    rb_define_method(cIP6Packet, "ip6_ver",    ip6p_ver,    0);
    rb_define_method(cIP6Packet, "ip6_tclass", ip6p_tclass, 0);
    rb_define_method(cIP6Packet, "ip6_flow",   ip6p_flow,   0);
    rb_define_method(cIP6Packet, "ip6_plen",   ip6p_plen,   0);
    rb_define_method(cIP6Packet, "ip6_nxt",    ip6p_nxt,    0);
    rb_define_method(cIP6Packet, "ip6_hlim",   ip6p_hlim,   0);

}
