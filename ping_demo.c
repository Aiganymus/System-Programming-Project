#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>

#include <linux/kfifo.h>
#include <linux/slab.h>

#include <linux/kthread.h>  
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>

static struct nf_hook_ops nfho;
static struct kfifo fifo;
static struct task_struct *thread;

static DEFINE_SPINLOCK(locker);
static unsigned long flags;

struct packet_info {
	u32 *source_address;
	int type;
	uint16_t source_port;
};

static unsigned int icmp_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	if(!skb)
		return NF_ACCEPT;
	
	struct iphdr *iph = ip_hdr(skb);

	if(iph->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmph = icmp_hdr(skb);

		struct packet_info *packet_info = kmalloc(sizeof(struct packet_info), GFP_KERNEL);
		packet_info->source_address = &iph->saddr;
		packet_info->type = icmph->type;

		struct tcphdr *tcph = tcp_hdr(skb);
		packet_info->source_port = ntohs(tcph->source);

		spin_lock_irqsave(&locker, flags);	
		kfifo_in(&fifo, &packet_info, sizeof(packet_info));
		spin_unlock_irqrestore(&locker, flags);
	}
	
	return NF_ACCEPT;	
}

int print_info(void *unused) {
	while(!kthread_should_stop()) {	
		spin_lock_irqsave(&locker, flags);
		if(!kfifo_is_empty(&fifo)) {
			struct packet_info *val = kmalloc(sizeof(struct packet_info), GFP_KERNEL);
			int ret = kfifo_out(&fifo, &val, sizeof(val));

			if (ret != sizeof(val))
				return -EINVAL;

			printk(KERN_INFO "ICMP ECHO REQUEST PACKET RECIEVED!");	
			printk(KERN_INFO "Source IP addres: %pI4\nSource port: %hu", val->source_address, val->source_port);
		}
		spin_unlock_irqrestore(&locker, flags);
	}
	return 0;
}

int init_module(void)
{
	int ret = kfifo_alloc(&fifo, PAGE_SIZE, GFP_KERNEL); 
	if (ret)
		return ret;

	nfho.hook = (nf_hookfn*) icmp_hookfn;  // hook function
	nfho.hooknum = NF_INET_LOCAL_IN;  // the packets destined for this machine
	nfho.pf = NFPROTO_IPV4;  // accept ipv4 protocol  
	nfho.priority = NF_IP_PRI_FIRST;  // priority of hook
	
	nf_register_net_hook(&init_net, &nfho);  // init_net - network namespace

	thread = kthread_run(print_info, NULL, "myPacketThread");
	if (thread) 
		printk(KERN_INFO "Thread IS created!");
	else
		printk(KERN_INFO "Thread Not created!");
	printk(KERN_INFO "Hello world!");
	
	return 0;
}

void cleanup_module(void)
{
	nf_unregister_net_hook(&init_net, &nfho);
	int res = kthread_stop(thread);
	printk(KERN_INFO "Goodbye world! %d", res);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aiganym");
MODULE_DESCRIPTION("Simple module for printing ICMP REQUEST information.");

