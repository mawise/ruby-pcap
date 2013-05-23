/*
 *  ip6_udp_packet.c
 *
 *  $Id: udp_packet.c,v 1.1.1.1 1999/10/27 09:54:38 fukusima Exp $
 *
 *  Copyright (C) 1999  Masaki Fukushima
 *
 *  Based on udp_packet.c by Masaki Fukushima
 *  Updates Copyright (C) 2013, Matthew Wise
 */

#include "ruby_pcap.h"
#include <limits.h>

#define IP6UDP_HDR(pkt)    ((struct udphdr *)LAYER4_HDR(pkt))
#define IP6UDP_DATA(pkt)   ((u_char *)LAYER5_HDR(pkt))
#define IP6UDP_LENGTH(pkt) (ntohs(IP6UDP_HDR(pkt)->uh_ulen))

VALUE cIP6UDPPacket;

#define CheckTruncateIp6Udp(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer4_off, need, "truncated UDP")

VALUE
setup_ip6_udp_packet(pkt, tl_len)
     struct packet_object *pkt;
     int tl_len;
{
    VALUE class;

    DEBUG_PRINT("setup_ip6_udp_packet");

    class = cIP6UDPPacket;
    if (tl_len > 8) {
        int hl = 8;
        int layer5_len;

        tl_len = MIN(tl_len, IP6UDP_LENGTH(pkt));
        layer5_len = tl_len - hl;
        if (layer5_len > 0) {
            pkt->hdr.layer5_off = pkt->hdr.layer4_off + hl;
            /* upper layer */
        }
    }
    return class;
}

#define IP6UDPP_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct udphdr *udp;\
    DEBUG_PRINT(#func);\
    GetPacket(self, pkt);\
    CheckTruncateIp6Udp(pkt, (need));\
    udp = IP6UDP_HDR(pkt);\
    return (val);\
}

IP6UDPP_METHOD(udpp_sport,   2, INT2FIX(ntohs(udp->uh_sport)))
IP6UDPP_METHOD(udpp_dport,   4, INT2FIX(ntohs(udp->uh_dport)))
IP6UDPP_METHOD(udpp_len,     6, INT2FIX(ntohs(udp->uh_ulen)))
IP6UDPP_METHOD(udpp_sum,     8, INT2FIX(ntohs(udp->uh_sum)))

static VALUE
udpp_data(self)
    VALUE self;
{
    struct packet_object *pkt;
    int len;

    DEBUG_PRINT("udpp_data");
    GetPacket(self, pkt);
    CheckTruncateUdp(pkt, 8);

    if (pkt->hdr.layer5_off == OFF_NONEXIST) return Qnil;

    len = MIN(Caplen(pkt, pkt->hdr.layer5_off), IP6UDP_LENGTH(pkt)-8);
    return rb_str_new(IP6UDP_DATA(pkt), len);
}

void
Init_ip6_udp_packet(void)
{
    DEBUG_PRINT("Init_ip6_udp_packet");

    /* define class UdpPacket */
    cIP6UDPPacket = rb_define_class_under(mPcap, "IP6UDPPacket", cIP6Packet);

    rb_define_method(cIP6UDPPacket, "udp_sport", udpp_sport, 0);
    rb_define_method(cIP6UDPPacket, "sport", udpp_sport, 0);
    rb_define_method(cIP6UDPPacket, "udp_dport", udpp_dport, 0);
    rb_define_method(cIP6UDPPacket, "dport", udpp_dport, 0);
    rb_define_method(cIP6UDPPacket, "udp_len", udpp_len, 0);
    rb_define_method(cIP6UDPPacket, "udp_sum", udpp_sum, 0);
    rb_define_method(cIP6UDPPacket, "udp_data", udpp_data, 0);
}
