#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/icmp.h>

#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops nfho;

static void printIPHeader(struct iphdr *icmph)
{
    printk(KERN_DEBUG "IP print function begin \n");
    printk(KERN_DEBUG "IP tos = %u\n", icmph->tos);
    printk(KERN_DEBUG "IP version = %u\n", icmph->version);
    printk(KERN_DEBUG "IP ihl = %u\n", icmph->ihl);
    printk(KERN_DEBUG "IP protocol = %u\n", icmph->protocol);
    printk(KERN_DEBUG "IP tot_len = %d\n", ntohs(icmph->tot_len));
    printk(KERN_DEBUG "IP frag_off = %d\n", ntohs(icmph->frag_off));
    printk(KERN_DEBUG "IP id = %d\n", ntohs(icmph->id));
    printk(KERN_DEBUG "IP ttl = %d\n", icmph->ttl);
    printk(KERN_DEBUG "IP check = %x\n", htons(icmph->check));
    printk(KERN_DEBUG "IP saddr = %d\n",  ntohl(icmph->saddr));
    printk(KERN_DEBUG "IP daddr = %d\n",  ntohl(icmph->daddr));
    printk(KERN_DEBUG "IP print function exit \n");       
}

static unsigned int icmp_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	if(!skb)
		return NF_DROP;
	
	struct iphdr *iph;
	struct icmphdr *icmph;

	iph = ip_hdr(skb);
	if(iph->protocol == IPPROTO_ICMP) {
		icmph = icmp_hdr(skb);
		
		if(icmph->type == ICMP_ECHO){
			printk(KERN_INFO "ICMP ECHO REQUEST PACKET BEING SEND!\n");
			/*struct ethhdr *ethh = eth_hdr(skb);
			printk(KERN_INFO "packet type ID field %d", ntohs(ethh->h_proto));
			struct ethhdr *ethh = eth_hdr(skb);
 			int i;
			for (i = 0; i < 6; i++) {
			  printk(KERN_INFO "%x", ethh->h_dest[i]);
			}
			for (i = 0; i < 6; i++) {
			  printk(KERN_INFO "%x", ethh->h_source[i]);
			}
			printk(KERN_INFO "skb truesize %u", skb->truesize);
			printk(KERN_INFO "skb network_header %hu", skb->network_header);
			printk(KERN_INFO "skb mac_header %hu", skb->mac_header);

			printk(KERN_INFO "net device in %s", state->in->name);
			printk(KERN_INFO "net device out %s", state->out->name);

			printk(KERN_DEBUG "ICMP id = %d\n", icmph->un.echo.id);
			printk(KERN_DEBUG "ICMP sequence = %d\n", icmph->un.echo.sequence);*/	
			//printIPHeader(iph);
			struct tcphdr *tcph = tcp_hdr(skb);
			printk(KERN_DEBUG "tcp dest = %d\n", ntohs(tcph->dest));
			printk(KERN_DEBUG "tcp source = %d\n", ntohs(tcph->source));

			struct udphdr *udph = udp_hdr(skb);
			printk(KERN_DEBUG "udp dest = %d\n", ntohs(udph->dest));
			printk(KERN_DEBUG "udp source = %d\n", ntohs(udph->source));

			printk(KERN_INFO "-------------------------------");
		}
		else if(icmph->type == ICMP_ECHOREPLY){
			printk(KERN_INFO "ICMP ECHO REPLY PACKET BEING SEND!\n");
			/*printk(KERN_INFO "skb truesize %u", skb->truesize);
			printk(KERN_INFO "skb network_header %hu", skb->network_header);
			printk(KERN_INFO "skb mac_header %hu", skb->mac_header);

			printk(KERN_INFO "net device in %s", state->in->name);
			printk(KERN_INFO "net device out %s", state->out->name);

			printk(KERN_DEBUG "ICMP id = %d\n", icmph->un.echo.id);
			printk(KERN_DEBUG "ICMP sequence = %d\n", icmph->un.echo.sequence);*/
			//printIPHeader(iph);
			printk(KERN_INFO "-------------------------------");
			/*printk(KERN_INFO "net device in %s", state->in->name);
			printk(KERN_INFO "net device out %s", state->out->name);
		    	printk(KERN_DEBUG "IP saddr = %d\n", iph->saddr);
		    	printk(KERN_DEBUG "IP daddr = %d\n", iph->daddr);*/	
		}
	}
	
	return NF_ACCEPT;	
}

int init_module(void)
{
	nfho.hook = (nf_hookfn*) icmp_hookfn;  // hook function
	nfho.hooknum = NF_INET_LOCAL_OUT;  
	nfho.pf = NFPROTO_IPV4;  // ipv4 protocol id  
	nfho.priority = NF_IP_PRI_FIRST;  // priority of hook
	
	nf_register_net_hook(&init_net, &nfho);

	printk(KERN_INFO "Hello world!\n");
	
	return 0;
}

void cleanup_module(void)
{
	nf_unregister_net_hook(&init_net, &nfho);
	
	printk(KERN_INFO "Goodbye world!\n");
}
