#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

#include <linux/skbuff.h>

#include <linux/ip.h>
#include <linux/icmp.h>

#include <linux/netdevice.h>

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <net/ip.h>

unsigned int inet_addr(char *str)
{
    int a, b, c, d;
    char arr[4];
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int *)arr;
}


int init_module(void)
{
	printk(KERN_INFO "Hello world!\n");

	struct net_device *net_dev = dev_get_by_name(&init_net, "lo");

	char *srcIP = "127.0.0.1";
	char *dstIP = "127.0.0.1";

	int icmp_hlen = 8;
	int ip_hlen = 20;

	int header_size = ETH_HLEN + icmp_hlen + ip_hlen; // 14+8+20=42bytes

//	struct sk_buff *skb = alloc_skb(1500, GFP_KERNEL);  // allocate memory for skb
	struct sk_buff *skb = netdev_alloc_skb(net_dev, 1500);
	skb_reserve(skb, header_size); 

	/* icmp header */
	struct icmphdr *icmph = (struct icmphdr*) skb_push(skb, icmp_hlen + sizeof(struct icmphdr));
	icmph->type = ICMP_ECHO;  // icmp echo request
	icmph->code = 0;
	icmph->un.echo.sequence = htons(256);
        icmph->un.echo.id = htons(current->pid);
	
	skb_reset_network_header(skb);

	/* ip header */
	struct iphdr* iph = (struct iphdr*) skb_push(skb, ip_hlen);
	iph->ihl = 5; 
	iph->version = 4;
  
	iph->tos = 0;  // type of service
	iph->tot_len = htons(84); 
	iph->id = htons(123);
	iph->frag_off = htons(IP_DF);
	iph->ttl = 64; // time to live
	iph->protocol = IPPROTO_ICMP; //  icmp protocol

	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	skb->csum_valid = 0;
	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

	iph->saddr = inet_addr(srcIP);
	iph->daddr = inet_addr(dstIP);

	skb_reset_network_header(skb);
	/*int ret = dev_hard_header(skb, net_dev, ETH_P_IP, addr, myaddr, net_dev->addr_len);
	printk(KERN_INFO "dev_hard_header: %d", ret);*/

	/* ethernet header */
	struct ethhdr* eth = (struct ethhdr*) skb_push(skb, sizeof (struct ethhdr));
	eth->h_proto = ETH_P_IP; /* 0x0800 Internet Protocol packet */
	memcpy(eth->h_source, net_dev->dev_addr, ETH_ALEN);
	memcpy(eth->h_dest, net_dev->dev_addr, ETH_ALEN);
	skb_reset_mac_header(skb);

	skb->protocol = ETH_P_IP;
	skb->dev = net_dev;
	skb->pkt_type = PACKET_OUTGOING;
	skb->priority = 0;

	struct icmphdr *icmph_test = icmp_hdr(skb); 
	printk(KERN_INFO "icmph_test %d", icmph_test->type);
	printk(KERN_INFO "skb len %d", skb->len);
	printk(KERN_INFO "skb data len %d", skb->data_len);
	printk(KERN_INFO "skb network_header %d", skb->network_header);
	printk(KERN_INFO "skb transport_header %d", skb->transport_header);
	struct ethhdr* eth_test = eth_hdr(skb);
	printk(KERN_INFO "eth  %u", eth_test->h_proto);

	/*if(dev_queue_xmit(skb)==NET_XMIT_SUCCESS)
		printk(KERN_INFO "dev_queue_xmit success!");*/
	
	kfree_skb(skb);
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Goodbye world!\n");
}
