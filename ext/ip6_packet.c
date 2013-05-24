/*
 *  ip6_packet.c
 *
 *  Copyright (C) 1998, 1999  Masaki Fukushima
 * 
 *  This file is based on ip_packet.c, Copyright Masaki Fukushima.
 *  The modifications for support of IPv6 are by Matthew Wise
 */

#include "ruby_pcap.h"
#include <netdb.h>

VALUE cIP6Packet;
static VALUE cIP6Address;

#define CheckTruncateIp6(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer3_off, need, "truncated IP6")

#define IP6_VERSION_MASK 0xf0
#define IP6_FLOWLABEL_MASK 0x000fffff
#define IP6_TRAFFICCLASS_MASK 0x0ff00000

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
    if (nl_len>40) {
       int tl_len = nl_len - 40;
       if (tl_len > 0) {
          pkt->hdr.layer4_off = pkt->hdr.layer3_off + 40; 
          switch (IP6_HDR(pkt)->ip6_nxt) {
          case IPPROTO_ICMPV6:
             class = setup_icmp6_packet(pkt, tl_len);
             break;
          case IPPROTO_TCP:
             class = setup_ip6_tcp_packet(pkt, tl_len);
             break;
          case IPPROTO_UDP:
             class = setup_ip6_udp_packet(pkt, tl_len);
             break;
          }
       }
    }
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


IP6P_METHOD(ip6p_ver,    1,  INT2FIX((ip6->ip6_vfc & IP6_VERSION_MASK)>>4))
IP6P_METHOD(ip6p_tclass, 4,  INT2FIX((ntohl(ip6->ip6_flow) & IP6_TRAFFICCLASS_MASK)>>20))
IP6P_METHOD(ip6p_flow,   4,  INT2FIX(ntohl(ip6->ip6_flow) & IP6_FLOWLABEL_MASK))
IP6P_METHOD(ip6p_plen,   6,  INT2FIX(ntohs(ip6->ip6_plen)))
IP6P_METHOD(ip6p_nxt,    7,  INT2FIX(ip6->ip6_nxt))
IP6P_METHOD(ip6p_hlim,   8,  INT2FIX(ip6->ip6_hlim))

IP6P_METHOD(ip6p_src,    24, new_ip6addr(&ip6->ip6_src))
IP6P_METHOD(ip6p_dst,    40, new_ip6addr(&ip6->ip6_dst))

static VALUE
ip6p_data(self)
      VALUE self;
{
    struct packet_object *pkt;
    struct ip6_hdr *ip6;
    int len, hlen;
    
    DEBUG_PRINT("ip6p_data");
    GetPacket(self, pkt);
    CheckTruncateIp6(pkt, 40);
    ip6 = IP6_HDR(pkt);

    hlen = 40;
    len = pkt->hdr.pkthdr.caplen - pkt->hdr.layer3_off - hlen;
    return rb_str_new((u_char *)ip6 + hlen, len);
}

/*
 * IPv6 Address
 */


#define GetIP6Address(obj, addr) {\
    Check_Type(obj, T_DATA);\
    Data_Get_Struct(obj, struct in6_addr, addr);\
}

VALUE
new_ip6addr(addr)
    struct in6_addr *addr;
{
    VALUE self;

    self = Data_Wrap_Struct(cIP6Address, 0, 0, (void *)addr);
    return self;
}

VALUE
ip6addr_to_a32(self)
    VALUE self;
{
    struct in6_addr *addr;
    VALUE array;
    int i;

    GetIP6Address(self, addr);
    array =  rb_ary_new();
    for ( i=0; i<4; i++) {
      rb_ary_push(array, UINT32_2_NUM(ntohl(addr->s6_addr32[i])));
    }
    return array;
}


VALUE
ip6addr_to_a16(self)
    VALUE self;
{
    struct in6_addr *addr;
    VALUE array;
    int i;

    GetIP6Address(self, addr);
    array =  rb_ary_new();
    for (i=0;i<8;i++) {
      rb_ary_push(array, INT2FIX(ntohs(addr->s6_addr16[i])));
    }
    return array;
}

VALUE
ip6addr_to_s(self)
    VALUE self;
{
    struct in6_addr *addr;
    char str[INET6_ADDRSTRLEN];    

    GetIP6Address(self, addr);
    inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);
    return rb_str_new2(str);
}

VALUE
ip6addr_equal(self, other)
    VALUE self, other;
{
    struct in6_addr *addr1;
    struct in6_addr *addr2;

    if ( rb_class_of(other) == cIP6Address) {
      GetIP6Address(self, addr1);
      GetIP6Address(other, addr2);
      if (IN6_ARE_ADDR_EQUAL(addr1, addr2)) {
        return Qtrue;
      }
    }
    return Qfalse;
}

static VALUE
ip6addr_hash(self)
    VALUE self;
{
    struct in6_addr *addr;
    GetIP6Address(self, addr);
    return UINT32_2_NUM(addr->s6_addr32[3]);
}


static VALUE
ip6addr_dump(self, limit)
     VALUE self;
     VALUE limit;
{
    struct in6_addr *addr;

    GetIP6Address(self, addr);
    return rb_str_new((char *)addr, sizeof addr);
}

static VALUE
ip6addr_s_load(klass, str)
     VALUE klass;
     VALUE str;
{
    struct in6_addr addr;
    int i;

    if (RSTRING_LEN(str) != sizeof addr) {
        rb_raise(rb_eArgError, "dump format error (IP6Address)");
    }
    for (i = 0; i < sizeof addr; i++) {
        ((char *)&addr)[i] = RSTRING_PTR(str)[i];
    }   
    return new_ip6addr(&addr);
}
 
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
    rb_define_method(cIP6Packet, "ip6_data",   ip6p_data,   0);

    rb_define_method(cIP6Packet, "ip6_src",    ip6p_src,    0);
    rb_define_method(cIP6Packet, "ip6_dst",    ip6p_dst,    0);

    cIP6Address = rb_define_class_under(mPcap, "IP6Address", rb_cObject);
    
    rb_define_method(cIP6Address, "to_a",      ip6addr_to_a32, 0);
    rb_define_method(cIP6Address, "to_a32",    ip6addr_to_a32, 0);
    rb_define_method(cIP6Address, "to_a16",    ip6addr_to_a16, 0);
    rb_define_method(cIP6Address, "to_s",      ip6addr_to_s,   0);
    rb_define_method(cIP6Address, "==",        ip6addr_equal,  1);
    rb_define_method(cIP6Address, "===",       ip6addr_equal,  1);
    rb_define_method(cIP6Address, "eql?",      ip6addr_equal,  1); 
    rb_define_method(cIP6Address, "hash",      ip6addr_hash,   0); 

    rb_define_method(cIP6Address, "_dump",     ip6addr_dump,   1);
    rb_define_singleton_method(cIP6Address, "_load", ip6addr_s_load, 1);  

    Init_icmp6_packet();
    Init_ip6_tcp_packet();
    Init_ip6_udp_packet();
}
