#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#include <linux/ip.h>
#include <linux/icmp.h>

#include <linux/kfifo.h>
#include <linux/slab.h>

static struct nf_hook_ops nfho;
static struct kfifo fifo;

struct packet_info {
	u32 *source_address;
	int type;
};

static unsigned int icmp_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	if(!skb)
		return NF_ACCEPT;
	
	struct iphdr *iph = ip_hdr(skb);

	if(iph->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmph = icmp_hdr(skb);

		if(icmph->type == ICMP_ECHO){
			printk(KERN_INFO "ICMP ECHO REQUEST PACKET RECIEVED!\n");	
			struct packet_info *packet_info = kmalloc(sizeof(struct packet_info), GFP_KERNEL);
			packet_info->source_address = &iph->saddr;
			packet_info->type = icmph->type;

			//printk(KERN_INFO "IP addres = %pI4\n", val->source_address);
			printk(KERN_INFO "-------------------------------");
		}
	}

	
	return NF_ACCEPT;	
}

int init_module(void)
{
	int ret;
	ret = kfifo_alloc(&fifo, PAGE_SIZE, GFP_KERNEL); 
	if (ret)
		return ret;
	nfho.hook = (nf_hookfn*) icmp_hookfn;  // hook function
	nfho.hooknum = NF_INET_LOCAL_IN;  // the packets destined for this machine
	nfho.pf = NFPROTO_IPV4;  // accept ipv4 protocol  
	nfho.priority = NF_IP_PRI_FIRST;  // priority of hook
	
	nf_register_net_hook(&init_net, &nfho);  // init_net - network namespace

	printk(KERN_INFO "Hello world!\n");
	
	return 0;
}

void cleanup_module(void)
{
	nf_unregister_net_hook(&init_net, &nfho);
	
	printk(KERN_INFO "Goodbye world!\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aiganym");
MODULE_DESCRIPTION("Simple module for printing ICMP REQUEST information.");

