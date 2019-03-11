#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/icmp.h>


static struct nf_hook_ops nfho;

static unsigned int icmp_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	if(!skb)
		return NF_DROP;
	
	struct iphdr *iph;
	struct icmphdr *icmph;
	
	iph = ip_hdr(skb);
	if(iph->protocol == IPPROTO_ICMP) {
		icmph = icmp_hdr(skb);
		if(icmph->type == ICMP_ECHOREPLY){
			printk(KERN_INFO "ICMP ECHO REPLY PACKET RECIEVED!\n");	
			printk(KERN_DEBUG "ICMP id = %d\n", icmph->un.echo.id);
			printk(KERN_DEBUG "ICMP sequence = %d\n", icmph->un.echo.sequence);
		}
	}

	
	return NF_ACCEPT;	
}

int init_module(void)
{
	nfho.hook = (nf_hookfn*) icmp_hookfn;  // hook function
	nfho.hooknum = NF_INET_LOCAL_IN;  // the packets destined for this machine
	nfho.pf = NFPROTO_IPV4;  // ipv4 protocol id  
	nfho.priority = NF_IP_PRI_FIRST;  // priority of hook
	
	nf_register_net_hook(&init_net, &nfho);

	printk(KERN_INFO "Hello world 1.\n");
	
	return 0;
}

void cleanup_module(void)
{
	nf_unregister_net_hook(&init_net, &nfho);
	
	printk(KERN_INFO "Goodbye world!\n");
}
