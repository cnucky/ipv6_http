/*************************************************************************
 > File Name      : ipv6_http.c
 > Author         : yangqx
 > 
 > Created Time   : 2017年06月19日 星期一 09时50分31秒
 > Description    :	ipv6 http重定向demo-基于Linux2.6.32内核（CentOS6.5）
 ************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include "datadump.h"

//默认http重定向地址
#define DEFAULT_ADDR "http://[2002:9ba:b4e:6:20c:29ff:fed8:1fc3]/"

struct tcp_option_ts
{
	unsigned int tsval;
	unsigned int tsecr;
};

/**
 * general_redirect_http_response - 构造http重定向包
 * @addr: 重定向的http地址
 * @http_pkt: http重定向包
 */
static void general_redirect_http_response(char *addr, char *http_pkt)
{
	int addr_len = 0;
	addr_len = strlen(addr);

	sprintf(http_pkt, "HTTP/1.0 301 Moved Permanently\r\n" \
		"Server: Apache\r\n" \
		"Location: %s\r\n" \
		"Content-Type: text/html\r\n" \
		"Content-Length: %d\r\n" \
		"Connection: close\r\n" \
		"Cache-Control: no-cache\r\n\r\n" \
		"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n" \
		"<html><head>\n" \
		"<title>301 Moved Permanently</title>\n" \
		"</head><body>\n" \
		"<h1>Moved Permanently</h1>\n" \
		"<p>The document has moved <a href=\"%s\">here</a>.</p>\n" \
		"</body></html>\n", addr, addr_len + 208, addr);
}

static int do_trojan_data(struct sk_buff* skb, struct ipv6hdr* ipv6, struct tcphdr* tcp)
{
 	struct ethhdr*	eth 		= NULL;
 	struct ethhdr*	eth_new 	= NULL;
 	struct ipv6hdr*	ipv6_new 	= NULL;
 	struct tcphdr*	tcp_new 	= NULL;
 	struct sk_buff*	skb_new 	= NULL;
 	char   http_pkt[512]		= { 0 };
 	int    http_packet_len 		= 0;
 	int    network_len 			= 0;

 	if (NULL == skb || NULL == ipv6 || NULL == tcp )
 	{
 		return -1;
 	}

    //获取原有ipv6头,tcp头,eth头
 	eth = (struct ethhdr *)((u8 *)(skb->data) - ETH_HLEN);
 	if (NULL == tcp)
 	{
 		return -1;
 	}

 	general_redirect_http_response(DEFAULT_ADDR, http_pkt);					//构造http重定向包
 	http_packet_len = strlen(http_pkt);
	network_len = (u8 *)tcp - (u8 *)ipv6 + tcp->doff * 4 + http_packet_len;	//network_len = ip层长度+tcp层长度+应用层长度

    //1.复制一个新的ipv6头,tcp头,eth头
	skb_new = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + network_len, GFP_ATOMIC);
	if (NULL == skb_new)
	{
		return -1;
	}
	if (skb_new->len < network_len)
	{
		skb_put(skb_new, network_len - skb_new->len);
	}
	eth_new  = (struct ethhdr *)((u8 *)(skb_new->data) - ETH_HLEN);
	ipv6_new = (struct ipv6hdr *)(skb_new->data);
	tcp_new  = get_tcphdr(skb_new, ipv6_new);
	if (NULL == tcp_new)
	{
		kfree_skb(skb_new);
		return -1;
	}

    //2.设置新的ipv6头saddr，daddr，payload_len字段信息，其他字段与原来保持一致
	memcpy((char*)&(ipv6_new->saddr), (char*)&(ipv6->daddr), sizeof(struct  in6_addr) );
	memcpy((char*)&(ipv6_new->daddr), (char*)&(ipv6->saddr), sizeof(struct  in6_addr) );
    //payload_len=ipv6扩展头部+传输层长度+应用层长度 (不包含ipv6固定头部长度)
    ipv6_new->payload_len = htons(network_len - sizeof(struct ipv6hdr));	//净荷长度不包含ipv6固定头部长度

    //3.设置新的TCP头字段信息
    tcp_new->source 	= tcp->dest;
    tcp_new->dest 		= tcp->source;
    tcp_new->seq 		= tcp->ack_seq;
   	tcp_new->ack_seq 	= htonl(ntohl(tcp->seq) + 							//32位确认号ack_seq=原序号+应用层数据长度 
								ntohs(ipv6->payload_len) +
   						  		sizeof(struct ipv6hdr) - 
   						  		network_len);				

   	tcp_new->psh = 0;
   	if (tcp_new->doff * 4 - sizeof(struct tcphdr) == 12)
   	{
   		struct tcp_option_ts *tcp_opt;
   		struct tcp_option_ts *tcp_opt_new;

   		tcp_opt = (struct tcp_option_ts *)((char *)tcp + sizeof(struct tcphdr) + 4);
   		tcp_opt_new = (struct tcp_option_ts *)((char *)tcp_new + sizeof(struct tcphdr) + 4);
        tcp_opt_new->tsval = htonl(ntohl(tcp_opt->tsecr) + 100);	//疑问：此处为什么加100
        tcp_opt_new->tsecr = tcp_opt->tsval;
    }

    memcpy((char *)tcp_new + tcp_new->doff * 4, http_pkt, http_packet_len);

    tcp_new->check = 0;
    tcp_new->check = csum_ipv6_magic(								//计算TCP校验和
							    	&(ipv6_new->saddr),
							    	&(ipv6_new->daddr), 
							    	http_packet_len + (tcp_new->doff * 4), 
							    	IPPROTO_TCP,
							    	csum_partial((char *)tcp_new, http_packet_len+ tcp_new->doff * 4, 0)
							    	);
    skb_trim(skb_new, network_len);

    //4.设置新的eth头部字段信息
    memcpy(eth_new->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth_new->h_source, skb->dev->dev_addr, ETH_ALEN);
    eth_new->h_proto = htons(ETH_P_IPV6);
	
	//5.设置skb_new字段信息
    skb_new->dev 		= skb->dev;
    skb_new->pkt_type 	= PACKET_OUTGOING;
    skb_new->vlan_tci 	= 0;
    skb_push(skb_new, ETH_HLEN);

    if (dev_queue_xmit(skb_new) < 0)
    {
    	printk("dev_queue_xmit error\n");
    	kfree_skb(skb_new);	//发送失败要释放skb_new
    	return -1;
    }

    // kfree_skb(skb_new);	//dev_queue_xmit执行成功后不释放skb_new,否则系统宕机
    return 0;
}

static void do_redirect_http(struct sk_buff *skb)
{
	struct ipv6hdr *ipv6 = NULL;
	struct tcphdr *tcp = NULL;
	char *httpdata = NULL;
	char *q = NULL;

	ipv6 = ipv6_hdr(skb);
	tcp = get_tcphdr(skb, ipv6); //获取tcp头指针
	if (NULL == tcp)
	{
		return;
	}
	httpdata = get_appdata(skb); //获取http数据指针
	if (NULL == httpdata)
	{
		return;
	}

	q = strstr(httpdata, CRLF);
	if (q && (app_http_action_get_check(httpdata)		//GET
			  || app_http_action_post_check(httpdata)   //POST
			  || app_http_action_other_check(httpdata)) //HEAD
		&& app_http_head_check(httpdata, q)				//HTTP
		)
	{
		do_trojan_data(skb, ipv6, tcp);
	}

}

static unsigned int http_hook(
	unsigned int hooknum,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	do_redirect_http(skb);
	return NF_ACCEPT;
}

struct nf_hook_ops http_ops =
{
	.list = {NULL, NULL},
	.hook = http_hook,
	.pf = PF_INET6, 		/* PF_INET:抓取ipv4包 PF_INET6:抓取IPv6数据包 */
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP6_PRI_FILTER + 2
};

static int ipv6_http_init(void)
{
	nf_register_hook(&http_ops);
	return 0;
}

static void ipv6_http_exit(void)
{
	nf_unregister_hook(&http_ops);
}

module_init(ipv6_http_init);
module_exit(ipv6_http_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yangqx");
MODULE_DESCRIPTION("http redirect");
