/*
 *  icmp6_packet.c
 *
 *  Copyright (C) 1999  Masaki Fukushima
 *
 * This file adapted from icmp_packet.c
 * Changes by Matthew Wise, (C) 2013 Matthew Wise
 */

#include "ruby_pcap.h"
#include <netinet/icmp6.h>

#define ICMP6_HDR(pkt)  ((struct icmp6_hdr *)LAYER4_HDR(pkt))
#define ICMP6_DATA(pkt) ((u_char *)LAYER5_HDR(pkt))
#define ICMP6_DATALEN(pkt) \
    (ntohs(IP6_HDR(pkt)->ip6_plen) - (8))
#define ICMP6_CAPLEN(pkt) (pkt->hdr.pkthdr.caplen - pkt->hdr.layer4_off)

VALUE cICMP6Packet;
VALUE cICMP6EchoPacket;
VALUE cICMP6ErrorPacket;

#define CheckTruncateICMP6(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer4_off, need, "truncated ICMP6")

VALUE
setup_icmp6_packet(pkt, tl_len)
     struct packet_object *pkt;
     int tl_len;
{
    VALUE klass =  cICMP6Packet;

    if (tl_len >= 1) {
        switch (ICMP6_HDR(pkt)->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
        case ICMP6_ECHO_REPLY:
           klass = cICMP6EchoPacket;
           break;
        case ICMP6_DST_UNREACH:
        case ICMP6_PACKET_TOO_BIG:
        case ICMP6_TIME_EXCEEDED:
        case ICMP6_PARAM_PROB:
           klass = cICMP6ErrorPacket;
           break;
        }
    }
    return klass;
}


#define ICMP6P_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct icmp6_hdr *icmp6;\
    GetPacket(self, pkt);\
    CheckTruncateICMP6(pkt, (need));\
    icmp6 = ICMP6_HDR(pkt);\
    return (val);\
}

/*
 * Common methods (icmp_type independent)
 */

ICMP6P_METHOD(icmp6p_type,   1, INT2FIX(icmp6->icmp6_type))
ICMP6P_METHOD(icmp6p_code,   2, INT2FIX(icmp6->icmp6_code))
ICMP6P_METHOD(icmp6p_cksum,  4, INT2FIX(ntohs(icmp6->icmp6_cksum)))

			 			 
/*
 * icmp_type specific methods
 */

ICMP6P_METHOD(icmp6p_id,     6, INT2FIX(ntohs(icmp6->icmp6_id)))
ICMP6P_METHOD(icmp6p_seq,    8, INT2FIX(ntohs(icmp6->icmp6_seq)))

icmp6p_pkt(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct icmp6_hdr *icmp6;
    struct pcap_pkthdr pkthdr;

    GetPacket(self, pkt);
    CheckTruncateICMP6(pkt, 9);
    icmp6 = ICMP6_HDR(pkt);

    pkthdr.caplen     = ICMP6_CAPLEN(pkt) - 8;
    pkthdr.len        = 0;
    pkthdr.ts.tv_sec  = 0;
    pkthdr.ts.tv_usec = 0;
    return new_packet((char *)&icmp6->icmp6_data8+4, &pkthdr, DLT_RAW);
}

ICMP6P_METHOD(icmp6p_data,  9, rb_str_new(icmp6->icmp6_data8, ICMP6_CAPLEN(pkt)-8))

void
Init_icmp6_packet(void)
{
    rb_define_const(mPcap, "ICMP6_ECHO_REQUEST",   INT2NUM(ICMP6_ECHO_REQUEST));
    rb_define_const(mPcap, "ICMP6_ECHO_REPLY",     INT2NUM(ICMP6_ECHO_REPLY));

    rb_define_const(mPcap, "ICMP6_DST_UNREACH",    INT2NUM(ICMP6_DST_UNREACH));
    rb_define_const(mPcap, "ICMP6_PACKET_TOO_BIG", INT2NUM(ICMP6_PACKET_TOO_BIG));
    rb_define_const(mPcap, "ICMP6_TIME_EXCEEDED",  INT2NUM(ICMP6_TIME_EXCEEDED));
    rb_define_const(mPcap, "ICMP6_PARAM_PROB",     INT2NUM(ICMP6_PARAM_PROB));

    cICMP6Packet = rb_define_class_under(mPcap, "ICMP6Packet", cIP6Packet);
    rb_define_method(cICMP6Packet, "icmp6_type",     icmp6p_type, 0);
    rb_define_method(cICMP6Packet, "icmp6_code",     icmp6p_code, 0);
    rb_define_method(cICMP6Packet, "icmp6_cksum",    icmp6p_cksum, 0);

    cICMP6EchoPacket = rb_define_class_under(mPcap, "ICMP6EchoPacket", cICMP6Packet);
    rb_define_method(cICMP6EchoPacket, "icmp6_id",        icmp6p_id, 0);
    rb_define_method(cICMP6EchoPacket, "icmp6_seq",       icmp6p_seq, 0);
    rb_define_method(cICMP6EchoPacket, "icmp6_data",      icmp6p_data, 0);

    cICMP6ErrorPacket = rb_define_class_under(mPcap, "ICMP6ErrorPacket", cICMP6Packet);
    rb_define_method(cICMP6ErrorPacket, "icmp6_pkt",        icmp6p_pkt, 0);

}
