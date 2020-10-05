#include "common.h"
#include "arp.h"
#include "ether.h"
#include "pktbuf.h"
#include "iface.h"

struct arp_entry *arp_base;
static int count;

void arp_init(){
    arp_base = NULL;
}

static void arp_valid(const struct arp_entry *arp){
    struct pktbuf *pbuf = pktbuf_alloc2(ETH_HDR_LEN + ARP_HDR_LEN);
    pbuf->data += ETH_HDR_LEN;
    pbuf->len += ARP_HDR_LEN;

    struct arp_hdr *arph = (struct arp_hdr *)pbuf->data;

    arph->hwtype = htons(0x0001);
    arph->hwlen = 6;
    arph->proto = htons(ETH_TYPE_IP);
    arph->protolen = 4;
    arph->opcode = htons(0x0001);
    arph->dipaddr.addr = arp->ip_addr.addr;
    arph->sipaddr.addr = arp->iface->ipaddr->ip.addr;
    memcpy(&arph->shwaddr, &arp->iface->eth_addr, 6);
    memcpy(&arph->dhwaddr, &arp->eth_addr, 6);
    pbuf->iface = arp->iface;

    eth_send(&arph->dhwaddr, &arph->shwaddr, ETH_TYPE_ARP, pbuf);
}

static int arp_reply(int hwtype, int proto, struct ip_addr *dipaddr, struct eth_addr *dhwaddr,
    struct ip_addr *sipaddr, struct iface *ifa){
    struct pktbuf *pbuf = pktbuf_alloc2(ETH_HDR_LEN + ARP_HDR_LEN);
    pbuf->data += ETH_HDR_LEN;
    pbuf->len += ARP_HDR_LEN;

    struct arp_hdr *arph = (struct arp_hdr *)pbuf->data;

    arph->hwtype = hwtype;
    arph->hwlen = 6;
    arph->proto = proto;
    arph->protolen = 4;
    arph->opcode = htons(ARP_OP_REPLY);
    arph->dipaddr = *dipaddr;
    arph->dhwaddr = *dhwaddr;
    arph->sipaddr = *sipaddr;
    memcpy(&arph->shwaddr, &ifa->eth_addr, 6);
    pbuf->iface = ifa;

    eth_send(dhwaddr, &ifa->eth_addr, ETH_TYPE_ARP, pbuf);
}

int arp_recv(struct pktbuf *pktbuf){
    struct arp_hdr *arph;
    struct ip_addr sipaddr, dipaddr;
    struct eth_addr shwaddr;
    struct iface *ifa;

    arph = arphdr(pktbuf);
    sipaddr = arph->sipaddr;
    dipaddr = arph->dipaddr;

    DBG(("arp_recv hwtype:%04x proto:%04x hwlen:%x protolen:%x opcode:%02x shw:%02x:%02x:%02x:%02x:%02x:%02x "
         "sip:%u dhw:%02x:%02x:%02x:%02x:%02x:%02x dip:%u\n",
         ntohs(arph->hwtype), ntohs(arph->proto), arph->hwlen, arph->protolen, arph->opcode,
         arph->shwaddr.addr[0], arph->shwaddr.addr[1], arph->shwaddr.addr[2], arph->shwaddr.addr[3],
         arph->shwaddr.addr[4], arph->shwaddr.addr[5],
         htonl(arph->sipaddr.addr),
         arph->dhwaddr.addr[0], arph->dhwaddr.addr[1], arph->dhwaddr.addr[2], arph->dhwaddr.addr[3],
         arph->dhwaddr.addr[4], arph->dhwaddr.addr[5],
         htonl(arph->dipaddr.addr)));

    IFACE_FOREACH(ifa){
        struct ipaddr *ipaddr;
        int found;
        ipaddr = ifa->ipaddr;
        for(int i = 0; i < 8; i ++){
            if(dipaddr.addr == ipaddr->ip.addr){
                found = 1;
                break;
            }
            ipaddr++;
        }
        if(found)
            break;
        DBG(("not for us, ignore arp request\n"));
        return 0;
    }

    sipaddr.addr = sipaddr.addr;
    arp_add(pktbuf->iface, &sipaddr, &arph->shwaddr);

    switch(ntohs(arph->opcode)){
    case ARP_OP_REQUEST:
        arp_reply(arph->hwtype, arph->proto, &sipaddr, &arph->shwaddr,
                 &dipaddr, ifa);
        break;
    default:
        DBG(("arp_recv unknow arp opcode %2x\n", ntohs(arph->opcode)));
        break;
    }

    pktbuf_free(pktbuf);
}

struct arp_entry *arp_add(struct iface *ifa, const struct ip_addr *ipaddr, struct eth_addr *ethaddr){
    int i;
    int empty = 0;
    int oldest = 0;
    struct arp_entry *entry;

    for(entry = arp_base; entry != NULL; entry = entry->next){
        DBG(("arp_add %02x:%02x:%02x:%02x:%02x:%02x %u\n",
            entry->eth_addr.addr[0], entry->eth_addr.addr[1], entry->eth_addr.addr[2],
            entry->eth_addr.addr[3], entry->eth_addr.addr[4], entry->eth_addr.addr[5],
            entry->ip_addr.addr));

        if(ipaddr->addr == entry->ip_addr.addr){
            entry->update_time = jiffies;
            DBG(("arp entry found\n"));
            return entry;
        }
    }

    if(count > ARP_TABLE_SIZE){
        INFO(("arp table is full\n"));
        return NULL;
    }

    entry = malloc(sizeof(struct arp_entry));
    entry->state = ARP_STATE_STABLE;
    entry->ip_addr.addr = ipaddr->addr;
    entry->update_time = jiffies;
    entry->iface = ifa;
    count++;

    memcpy(entry->eth_addr.addr, ethaddr->addr, 6);
    entry->next = NULL;

    if(!arp_base){
        arp_base = entry;
    }

    return entry;
}

struct arp_entry *arp_lookup(struct iface *ifa,  const struct ip_addr *ipaddr){
    struct arp_entry *entry;
    struct pktbuf *pbuf;
    char buf[32];

    ARP_FOREACH(entry){
        if(htonl(ipaddr->addr) == entry->ip_addr.addr){
            entry->last_time = jiffies;
            return entry;
        }
    }

    DBG(("arp entry not found for %s\n", ntoa(ipaddr->addr, buf)));

    pbuf = pktbuf_alloc2(ETH_HDR_LEN + ARP_HDR_LEN);
    pbuf->data += ETH_HDR_LEN;
    pbuf->len += ARP_HDR_LEN;

    struct arp_hdr *arph = (struct arp_hdr *)pbuf->data;

    arph->hwtype = htons(0x0001);
    arph->hwlen = 6;
    arph->proto = htons(ETH_TYPE_IP);
    arph->protolen = 4;
    arph->opcode = htons(0x0001);
    arph->dipaddr.addr = htonl(ipaddr->addr);
    arph->sipaddr.addr = ifa->ipaddr->ip.addr;
    memcpy(&arph->shwaddr, &ifa->eth_addr, 6);
    pbuf->iface = ifa;

    eth_send(NULL, &arph->shwaddr, ETH_TYPE_ARP, pbuf);

    return NULL;
}

void arp_task(){
    struct arp_entry *entry;
    struct arp_entry *prev;
    long time, tmp;

    prev = NULL;
    for(entry = arp_base; entry != NULL; entry = entry->next){
        if(jiffies - entry->last_time < 5 && jiffies - entry->update_time > 20){
            arp_valid(entry);
        }else if(jiffies - entry->update_time > ARP_TIMEOUT){
            DBG(("delete arp entry %u\n", entry->ip_addr.addr));
            if(!prev){
                arp_base = NULL;
                free(entry);
                break;
            }
            prev->next = entry->next;
            entry = prev;
            free(entry);
            count--;
            continue;
        }
        prev = entry;
    }
}
