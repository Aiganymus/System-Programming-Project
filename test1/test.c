#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/icmp.h>


static struct nf_hook_ops nfho;

static void printIPHeader(struct iphdr *icmph)
{
    printk(KERN_DEBUG "IP print function begin \n");
    printk(KERN_DEBUG "IP tos = %d\n", icmph->tos);
    printk(KERN_DEBUG "IP tot_len = %u\n", ntohs(icmph->tot_len));
    printk(KERN_DEBUG "IP frag_off = %u\n", ntohs(icmph->frag_off));
    printk(KERN_DEBUG "IP id = %d\n", icmph->id);
    printk(KERN_DEBUG "IP ttl = %d\n", icmph->ttl);
    printk(KERN_DEBUG "IP check = %d\n", icmph->check);
    printk(KERN_DEBUG "IP saddr = %d\n", icmph->saddr);
    printk(KERN_DEBUG "IP daddr = %d\n", icmph->daddr);
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
	
			
			printk(KERN_INFO "net device in %s", state->in->name);
			printk(KERN_INFO "net device out %s", state->out->name);

			printk(KERN_DEBUG "ICMP id = %d\n", icmph->un.echo.id);
			printk(KERN_DEBUG "ICMP sequence = %d\n", icmph->un.echo.sequence);	
			printk(KERN_INFO "-------------------------------");
			//printIPHeader(iph);
		}
		else if(icmph->type == ICMP_ECHOREPLY){
			printk(KERN_INFO "ICMP ECHO REPLY PACKET BEING SEND!\n");
	
			printk(KERN_INFO "net device in %s", state->in->name);
			printk(KERN_INFO "net device out %s", state->out->name);

			printk(KERN_DEBUG "ICMP id = %d\n", icmph->un.echo.id);
			printk(KERN_DEBUG "ICMP sequence = %d\n", icmph->un.echo.sequence);
			printk(KERN_INFO "-------------------------------");
			/*printk(KERN_INFO "net device in %s", state->in->name);
			printk(KERN_INFO "net device out %s", state->out->name);
		    	printk(KERN_DEBUG "IP saddr = %d\n", iph->saddr);
		    	printk(KERN_DEBUG "IP daddr = %d\n", iph->daddr);*/	
			//printIPHeader(iph);
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
