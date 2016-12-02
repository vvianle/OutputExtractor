#TRUSTED 5a0b36e72fb8cf83dc8fe835dcbc7cca8a898aed08eb31bbb297f2d8a49291bc7bf97bda75c53eba4e06c22a6b542948d4705d6cdbdd675ef8abc4e5b2cb6766a1eff13db2caef553b06921a5c6d51ea3a2d52e1c2e6871c2d547c4a80aa712e675f2036e30065a1cd4df26204c9377131702ccf7ba506b58fae41404346ee57d3573f88c403dafd2585453b36bfca6b90093b02b29521eea2e9ff6053e1a40c0fe0d70f7360e6f5d0ee96b41cd3836aabf545463fa7c581afa0223d2941b13c30742c4b1ff8b015e7f805f4fbda1b5e76d0b8da5ec91f154f67ffa0d43dca0e53a245171dfd2b6f80e9eeddc230b0f4cdb25b255a88d33229ed429d66cf2d4ccbcc64c361834670851adc17a43a748d3d62133181a95de22e004a18899c1352f6ca6f5b6f3041c078a93e68b44234bd59028efdc2f52732de2fa01c7166e709265d4aed9f84426a580ef5e467af02ae23f7b4f2407792947abec21a28c06ac67cfb2f17c0c4b18fba0623b27eaedc01f48a31441db1c6f434ca1956da7ab1eb30710e0ca2a776fcc79a0c7be255f64885245de07aa63200a4605def4c1df715ccd2f522381e9cee0c081b7a17098b9e8725737aedcc211ba2e2d115020df5469f6f8c726ea11bfd8156689365c145becd7765968305ca0915153db9acd6496f1d0519e515a88dd10e76084aedd2f89bc33c282fd39f4483763d1ae43f92fa12
#
#
# (C) Tenable Network Security, Inc.
# @NOGPL@
#
#
# This file is used by the functions start_denial()/end_denial(). Do not edit it !!
#


# 
# Utilities
#
function mkbyte()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return raw_string(l & 0xff);
}

function mkword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return  raw_string((l >> 8) & 0xFF, l & 0xFF);
}

function mkipaddr()
{
 local_var ip;
 local_var str;

 ip = _FCT_ANON_ARGS[0];
 str = split(ip, sep:'.', keep:FALSE);
 return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3])); 
}



 

function arp_ping()
{
 local_var broadcast, macaddr, ethernet, arp, r, i, srcip, dstmac, t1, t2;

 broadcast = crap(data:raw_string(0xff), length:6);
 macaddr   = get_local_mac_addr();

 if ( ! macaddr ) return 0;  # Not an ethernet interface

 arp       = mkword(0x0806); 


 ethernet = broadcast + macaddr + arp;

 arp      = ethernet +              			# Ethernet
           mkword(0x0001) +        			# Hardware Type
           mkword(0x0800) +        			# Protocol Type
           mkbyte(0x06)   +        			# Hardware Size
           mkbyte(0x04)   +        			# Protocol Size
           mkword(0x0001) +        			# Opcode (Request)
           macaddr        +        			# Sender mac addr
           mkipaddr(this_host()) + 			# Sender IP addr
           crap(data:raw_string(0), length:6) + 	# Target Mac Addr
           mkipaddr(get_host_ip());

 t1 = gettimeofday();
 for ( i = 0 ; i < 3 ; i ++ )
{
 r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + get_host_ip(), timeout:1);
 if ( r && strlen(r) > 31 ) 
  {
  t2 = gettimeofday();
  srcip = substr(r, 28, 31);
  if ( srcip == mkipaddr(get_host_ip() ) )
    return 1;
  }
}
 return 0;
}


if(islocalhost()) return 1;

if ( TARGET_IS_IPV6 ) return 1;


if ( islocalnet() && !TARGET_IS_IPV6 ) 
  return arp_ping();

if (tcp_ping()) return 1;

# Try ICMP ping
pfilter = "src host " + get_host_ip()+ " and dst host " + this_host() +
	 " and ( icmp and icmp[0]=0 or tcp )";
# and ((tcp[13] & 23) == 18)

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0,ip_len:20,
     		       ip_p:IPPROTO_ICMP, ip_id: rand() % 65536, ip_ttl:0x40,
 		       ip_src:this_host());
icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
 			    icmp_seq: rand() % 65536, icmp_id: rand() % 65535);

for (i = 1; i < 4; i ++)
{
 r =  send_packet(icmp, pcap_active:TRUE, pcap_filter: pfilter, pcap_timeout: i);
 if (r) return 1;
}

# Try again TCP
try_ports_l = make_list(22, 23, 53, 79, 111, 113, 135, 139, 143, 264, 389, 443, 445, 497, 515, 548, 993, 1025, 1027, 1454, 1723, 1917, 1028, 1029, 2869, 3389, 5000, 6000, 9100);
 foreach port (try_ports_l)
  if (get_port_state(port))
  {
   ip = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 40,
                        ip_id : rand() % 65535,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 64,
                        ip_off : 0,
			ip_src : this_host());
    if ( ! ip ) return 1;
    tcp = forge_tcp_packet(ip       : ip,
                           th_sport : 1024 + rand() % 64512,
                           th_dport : port,
                           th_flags : TH_SYN,
                           th_seq   : rand(),
                           th_ack   : 0,
                           th_x2    : 0,
                           th_off   : 5,
                           th_win   : 512);
    if ( ! tcp ) return 1;
    r = send_packet(tcp, pcap_active:TRUE, pcap_filter: pfilter, pcap_timeout: 0);
    if (r) return 1;
  }

to = int(get_preference("checks_read_timeout")); if (! to) to = 5;
r = pcap_next(pcap_filter: pfilter, timeout: to);
if (r) return 1;

# No answer - this file MUST end with "return TRUE / FALSE"
return 0;

