/*************************************************************************
 > File Name      : datadump.h
 > Author         : yangqx
 > 
 > Created Time   : 2017年06月19日 星期一 15时31分21秒
 > Description    : 打印抓包数据函数 
 ************************************************************************/

#ifndef __DATADUMP_H__
#define __DATADUMP_H__

#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <linux/ipv6.h>
#include <linux/netfilter_ipv6.h>

#define CRLF 		"\r\n"
#define TRUE        1
#define FALSE       0

#define NIPOCTU(addr)			\
 ntohs((addr).s6_addr16[0]),	\
 ntohs((addr).s6_addr16[1]),	\
 ntohs((addr).s6_addr16[2]),	\
 ntohs((addr).s6_addr16[3]), 	\
 ntohs((addr).s6_addr16[4]), 	\
 ntohs((addr).s6_addr16[5]), 	\
 ntohs((addr).s6_addr16[6]), 	\
 ntohs((addr).s6_addr16[7])

#define ETHSIXTU(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

//获取TCP头指针，必须检查返回值
struct tcphdr *get_tcphdr(struct sk_buff *skb, struct ipv6hdr *ipv6h)
{
	// if (NULL == ipv6h) return NULL;
	struct tcphdr *tcph = NULL;
	int tcphoff = 0;
	u8  nexthdr = 0;

	nexthdr = ipv6h->nexthdr;

	tcphoff = ipv6_skip_exthdr(skb, sizeof(*ipv6h), &nexthdr);
	if (tcphoff < 0)
	{
		printk("ipv6_skip_exthdr error\n");
		return NULL;
	}

	// printk("tcphoff = %d, nexthdr = %d\n", tcphoff, nexthdr);
	if (nexthdr == IPPROTO_TCP)
	{
		tcph = (struct tcphdr *)((u8 *)ipv6h + tcphoff);
    	// printk("tcp: src port = %d, dst port = %d\n", ntohs(tcph->source), ntohs(tcph->dest));
		return tcph;
	}

	return NULL;
}

//获取应用层数据指针，必须检查返回值
char* get_appdata(struct sk_buff* skb)
{
	struct ipv6hdr* ipv6 = NULL;
	struct tcphdr* 	tcp  = NULL;
	char*  app_data 	 = NULL;

	ipv6 = ipv6_hdr(skb);

	tcp = get_tcphdr(skb, ipv6);
	if (NULL == tcp)
	{
		return NULL;
	}
	app_data = (char *)tcp + tcp->doff * 4;
	return app_data;
}

void print_skb(struct sk_buff *skb)
{
	printk("skb->dev = %s, skb->protocol = 0x%x, skb->pkt_type = 0x%x\n", 
			skb->dev->name, 
			ntohs(skb->protocol), 
			ntohs(skb->pkt_type));
	printk("skb->data = 0x%lx, mac_header = 0x%lx, network_header = 0x%lx, transport_header = 0x%lx\n",
			(long )skb->data, 
			(long )skb->mac_header, 
			(long )skb->network_header, 
			(long )skb->transport_header);
	printk("skb->len=0x%x, skb->data_len=0x%x\n", 
			(unsigned int)skb->len, 
			(unsigned int)skb->data_len);
	printk("skb->head=0x%lx, skb->end=0x%x, skb->tail=0x%x\n", 
			(long )skb->head, 
			(unsigned int )skb->end, 
			(unsigned int )skb->tail);
}

//打印ethhdr字段信息
void print_eth(struct ethhdr *eth_new)
{
	printk("ethhdr = 0x%lx, ", (long )eth_new);
	printk("ETH_HLEN=%d, ETH_ALEN=%d\n", ETH_HLEN, ETH_ALEN);
	printk("h_proto=0x%x, src = %02x-%02x-%02x-%02x-%02x-%02x, dst = %02x-%02x-%02x-%02x-%02x-%02x\n",
			ntohs(eth_new->h_proto),
			ETHSIXTU(eth_new->h_source),
			ETHSIXTU(eth_new->h_dest));
}

//打印ipv6头字段信息
void print_ipv6(struct ipv6hdr *ipv6h)
{
	printk("ipv6h = 0x%lx， sizeof(ipv6hdr)=%ld\n", (long )ipv6h, sizeof(struct ipv6hdr) );
	printk("ip version = %d, src=[%x:%x:%x:%x:%x:%x:%x:%x], dst=[%x:%x:%x:%x:%x:%x:%x:%x]\n",
			ipv6h->version,
			NIPOCTU(ipv6h->saddr),
			NIPOCTU(ipv6h->daddr));
	printk("priority = %d, payload_len=%d, nexthdr=%d, hop_limit=%d, flow_lbl=[0x%x, 0x%x, 0x%x]\n",
			ipv6h->priority,
			ntohl(ipv6h->payload_len),
			ipv6h->nexthdr,
			ipv6h->hop_limit,
			ipv6h->flow_lbl[0], 
			ipv6h->flow_lbl[1], 
			ipv6h->flow_lbl[2]);
}

void print_tcp(struct tcphdr *tcp)
{
	printk("tcp = 0x%lx\n", (long )tcp);
	printk("src port = %d, dest port = %d, seq=0x%x, ack_seq=0x%x, doff=%d\n",
			ntohs(tcp->source), 
			ntohs(tcp->dest),
			tcp->seq, 
			tcp->ack_seq, 
			tcp->doff);
	printk("fin=%d,syn=%d,rst=%d,ack=%d,window=%d\n", 
			tcp->fin, 
			tcp->syn, 
			tcp->rst, 
			tcp->ack, 
			ntohs(tcp->window));

}

//字符串查找函数
char* gd_strnstr(const char *s, const char *find, size_t slen)
{
    char c;
    char sc;
    size_t len;

    if ((c = *find++) != '\0')
    {
        len = strlen(find);
        do
        {
            do
            {
                if (slen < 1 || (sc = *s) == '\0')
                {
                    return (NULL);
                }
                --slen;
                ++s;
            } while (sc != c);

            if (len > slen)
            {
                return (NULL);
            }
        } while (strncmp(s, find, len) != 0);

        s--;
    }
    return (char *)s;
}

int app_http_head_check(char *s, char *t)
{
    if (gd_strnstr(s, "HTTP/", t - s))
    {
        return TRUE;
    }
    return FALSE;
}

int app_http_action_get_check(char *app_data)
{
    return 	!strncmp(app_data, "GET ", 4);
}

int app_http_action_post_check(char *app_data)
{
    return 	!strncmp(app_data, "POST ", 5); 
}

int app_http_action_other_check(char *app_data)
{
    return	!strncmp(app_data, "HEAD ",		5)	||
        	!strncmp(app_data, "PUT ", 		4)	||
        	!strncmp(app_data, "DELETE ", 	7)	||
        	!strncmp(app_data, "TRACE ", 	6) 	||
        	!strncmp(app_data, "OPTIONS ", 	8) 	||
        	!strncmp(app_data, "CONNECT ", 	8);
}

#endif 

