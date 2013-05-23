/*
 *  ip6_tcp_packet.c
 *
 *  $Id: tcp_packet.c,v 1.1.1.1 1999/10/27 09:54:38 fukusima Exp $
 *
 *  Copyright (C) 1998, 1999  Masaki Fukushima
 * 
 *  Based on tcp_packet.c by Masaki Fukushima 
 *  Updates Copyright (C) 2013, Matthew Wise
 */

#include "ruby_pcap.h"
#include <limits.h>

#define IP6TCP_HDR(pkt)    ((struct tcphdr *)LAYER4_HDR(pkt))
#define IP6TCP_DATA(pkt)   ((u_char *)LAYER5_HDR(pkt))
#define IP6TCP_DATALEN(pkt) ((40) - (IP6TCP_HDR(pkt)->th_off) * 4)

VALUE cIP6TCPPacket;

#define CheckTruncateIp6Tcp(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer4_off, need, "truncated TCP")

VALUE
setup_ip6_tcp_packet(pkt, tl_len)
     struct packet_object *pkt;
     int tl_len;
{
    VALUE class;

    DEBUG_PRINT("setup_ip6_tcp_packet");

    class = cIP6TCPPacket;
    if (tl_len > 20) {
        int hl = IP6TCP_HDR(pkt)->th_off * 4;
        int layer5_len = tl_len - hl;
        if (layer5_len > 0) {
            pkt->hdr.layer5_off = pkt->hdr.layer4_off + hl;
            /* upper layer */
        }
    }
    return class;
}

#define IP6TCPP_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct tcphdr *tcp;\
    DEBUG_PRINT(#func);\
    GetPacket(self, pkt);\
    CheckTruncateIp6Tcp(pkt, (need));\
    tcp = IP6TCP_HDR(pkt);\
    return (val);\
}

IP6TCPP_METHOD(tcpp_sport,   2, INT2FIX(ntohs(tcp->th_sport)))
IP6TCPP_METHOD(tcpp_dport,   4, INT2FIX(ntohs(tcp->th_dport)))
IP6TCPP_METHOD(tcpp_seq,     8, UINT32_2_NUM(ntohl(tcp->th_seq)))
IP6TCPP_METHOD(tcpp_acknum, 12, UINT32_2_NUM(ntohl(tcp->th_ack)))
IP6TCPP_METHOD(tcpp_off,    13, INT2FIX(tcp->th_off))
IP6TCPP_METHOD(tcpp_flags,  14, INT2FIX(tcp->th_flags))
IP6TCPP_METHOD(tcpp_win,    16, INT2FIX(ntohs(tcp->th_win)))
IP6TCPP_METHOD(tcpp_sum,    18, INT2FIX(ntohs(tcp->th_sum)))
IP6TCPP_METHOD(tcpp_urp,    20, INT2FIX(ntohs(tcp->th_urp)))

#define IP6TCPP_FLAG(func, flag) \
    IP6TCPP_METHOD(func, 14, (tcp->th_flags & flag) ? Qtrue : Qfalse)
IP6TCPP_FLAG(tcpp_fin, TH_FIN)
IP6TCPP_FLAG(tcpp_syn, TH_SYN)
IP6TCPP_FLAG(tcpp_rst, TH_RST)
IP6TCPP_FLAG(tcpp_psh, TH_PUSH)
IP6TCPP_FLAG(tcpp_ack, TH_ACK)
IP6TCPP_FLAG(tcpp_urg, TH_URG)

static VALUE
tcpp_data(self)
     VALUE self;
{
    struct packet_object *pkt;
    VALUE v_len;
    int len;

    DEBUG_PRINT("tcpp_data");
    GetPacket(self, pkt);

    if (pkt->hdr.layer5_off == OFF_NONEXIST) return Qnil;

    len = MIN(Caplen(pkt, pkt->hdr.layer5_off), TCP_DATALEN(pkt));
    if (len < 1) return Qnil;
    return rb_str_new(TCP_DATA(pkt), len);
}

void
Init_ip6_tcp_packet(void)
{
    DEBUG_PRINT("Init_ip6_tcp_packet");

    /* define class TcpPacket */
    cIP6TCPPacket = rb_define_class_under(mPcap, "IP6TCPPacket", cIP6Packet);

    rb_define_method(cIP6TCPPacket, "tcp_sport", tcpp_sport, 0);
    rb_define_method(cIP6TCPPacket, "sport", tcpp_sport, 0);
    rb_define_method(cIP6TCPPacket, "tcp_dport", tcpp_dport, 0);
    rb_define_method(cIP6TCPPacket, "dport", tcpp_dport, 0);
    rb_define_method(cIP6TCPPacket, "tcp_seq", tcpp_seq, 0);
    rb_define_method(cIP6TCPPacket, "tcp_ack", tcpp_acknum, 0);
    rb_define_method(cIP6TCPPacket, "tcp_off", tcpp_off, 0);
    rb_define_method(cIP6TCPPacket, "tcp_hlen", tcpp_off, 0);
    rb_define_method(cIP6TCPPacket, "tcp_flags", tcpp_flags, 0);
    rb_define_method(cIP6TCPPacket, "tcp_win", tcpp_win, 0);
    rb_define_method(cIP6TCPPacket, "tcp_sum", tcpp_sum, 0);
    rb_define_method(cIP6TCPPacket, "tcp_urp", tcpp_urp, 0);
    rb_define_method(cIP6TCPPacket, "tcp_fin?", tcpp_fin, 0);
    rb_define_method(cIP6TCPPacket, "tcp_syn?", tcpp_syn, 0);
    rb_define_method(cIP6TCPPacket, "tcp_rst?", tcpp_rst, 0);
    rb_define_method(cIP6TCPPacket, "tcp_psh?", tcpp_psh, 0);
    rb_define_method(cIP6TCPPacket, "tcp_ack?", tcpp_ack, 0);
    rb_define_method(cIP6TCPPacket, "tcp_urg?", tcpp_urg, 0);
    rb_define_method(cIP6TCPPacket, "tcp_data", tcpp_data, 0);
}
