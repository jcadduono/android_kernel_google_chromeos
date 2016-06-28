/*
 * Copyright 2016 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bitops.h>
#include <linux/export.h>
#include <linux/debugfs.h>
#include <linux/spinlock.h>
#include <linux/idr.h>
#include <net/cfg80211.h>
#include <net/mac80211.h>
#include <net/ip.h>

#include "ieee80211_i.h"
#include "packet_trace.h"

/* Internal definitions */

struct packet_trace;

/* packet trace config flags */
#define PT_F_LOG_STA_CTL_CMD	BIT(0)
#define PT_F_LOG_WHEN_TAGGED	BIT(1)
#define PT_F_LOG_PRINT_TOKEN	BIT(2)
#define PT_F_LOG_PRINT_SUCCESS	BIT(3)

/* skb flags */
#define PT_F_TRACE_MGMT		BIT(0)
#define PT_F_TRACE_ETHERTYPE	BIT(1)
#define PT_F_TRACE_FRAMETYPE	BIT(2)
#define PT_F_TRACE		(BIT(0) | BIT(1) | BIT(2))

/**
 * struct packet_trace cookie - structure carrying packet trace tagging
 * information. It's set at TX and RX flow entrance and will be used by
 * subsequent logging calls.
 *
 * @flags: tracing flags
 * @id: information used for logging output
 * @token: used to follow packet and matching TX status
 */
struct packet_trace_cookie {
	u32 flags : 8;
	u32 id    : 8;
	u32 token : 16;
} __packed;

#define MAC80211_PT_MAX_FTYPES		8
#define MAC80211_PT_MAX_STYPES		16
#define MAC80211_PT_MAX_ETYPES		8

/* function prototype that handles predefined frame types */
typedef bool (*ftype_handler)(struct packet_trace *pt,
			      struct sk_buff *skb,
			      bool tx);

#define PT_MATCH_TYPE_NAME_MAX_SZ	15

/**
 * struct pt_match_type - match type info
 *
 * @name: match type string name
 */
struct pt_match_type {
	char name[PT_MATCH_TYPE_NAME_MAX_SZ + 1];
};

/**
 * struct ftype_def - predefined frame type handlers
 *
 * @enable: true if valid
 * @name: frame type name
 * @handler: frame type handler
 */
struct ftype_def {
	bool enable;
	char name[PT_MATCH_TYPE_NAME_MAX_SZ + 1];
	ftype_handler handler;
	u8 id;
};

/**
 * struct sta_def - stations to be traced
 *
 * @addr: MAC address of station
 */
struct sta_def {
	struct list_head list;
	u8 addr[ETH_ALEN];
};

/**
 * struct packet_trace - packet trace configuration per phy
 *
 * @flags: global flags
 * @tx_token_counter: tx token generator
 * @rx_token_counter: rx token generator
 * @num_ftypes: number of predefined frame types initialized
 * @ftypes: predefined frame type definiftions
 * @allowed_mgmt_stypes: MGMT subtypes allowed be traced
 * @traced_mgmt_stypes: MGMT subtypes enabled to trace
 * @num_etypes: number of ether types configured
 * @etypes: ether type configuration
 * @num_stations: number of stations configured
 * @stations: station MAC address configuration
 * @local: save the struct ieee80211_local pointer
 */
struct packet_trace {
	u32 flags;
	u16 tx_token_counter;
	u16 rx_token_counter;

	struct idr match_types;
	/* protect match type description lookup idr */
	spinlock_t match_type_lock;

	/* protects packet match configuration */
	spinlock_t match_config_lock;

	/* predefined frame types */
	int num_ftypes;
	struct ftype_def ftypes[MAC80211_PT_MAX_FTYPES];

	/* 802.11 MGMT STYPEs bitmask */
	u16 allowed_mgmt_stypes;
	u16 traced_mgmt_stypes;

	/* ether_types */
	int num_etypes;
	u16 etypes[MAC80211_PT_MAX_ETYPES];
	u8 etypes_id[MAC80211_PT_MAX_ETYPES];

	/* protects configure and lookup pf station_list */
	spinlock_t match_station_lock;
	int num_stations;
	struct list_head station_list;

	struct dentry *debugfsdir;
	void *local;
};

#define PT_MAX_INPUT_SZ	128
#define PT_MAX_ARGC	5

#define PT_LOG_INTERNAL(fmt, ...) pr_debug(fmt, ##__VA_ARGS__)

#define PT_LOG_DRIVER_STR_MAX_SZ	15
#define PT_LOG_STAMAC_STR_MAX_SZ	22
#define PT_LOG_COOKIE_STR_MAX_SZ	30
#define PT_LOG_PREFIX_STR_EXTRA_SZ	30
#define PT_LOG_PREFIX_STR_MAX_SZ	(PT_LOG_DRIVER_STR_MAX_SZ +	\
					PT_LOG_STAMAC_STR_MAX_SZ +	\
					PT_LOG_COOKIE_STR_MAX_SZ +	\
					PT_LOG_PREFIX_STR_EXTRA_SZ)

#define PT_CMD_STATUS_HANDLED	0
#define PT_CMD_STATUS_NOOP	1

/* Internal functions */

/**
 * pt_parse_mac - parse string into MAC address
 *
 * @str: MAC address string, in format of "aa:bb:cc:dd:ee:ff"
 * @addr: parsed MAC address
 *
 * Return: 0 on success, -1 on error
 */
static int pt_parse_mac(char *str, u8 *addr)
{
	char c;
	int i = 0;
	int val_h, val_l;

	eth_zero_addr(addr);
	while (*str && i < ETH_ALEN) {
		c = *str++;
		val_h = 0;
		val_l = hex_to_bin(c);
		if (val_l == -1)
			return -1;

		if (*str != '\0' && *str != ':') {
			c = *str++;
			val_h = val_l << 4;
			val_l = hex_to_bin(c);
			if (val_l == -1)
				return -1;
		}

		if (*str != '\0' && *str != ':')
			return -1;
		str++;

		addr[i++] = val_h + val_l;
	}

	return i;
}

/**
 * pt_parse_args - parse input string into argc count and argv array
 *
 * @str: input command string
 * @argv: parsed string segments
 * @max_argc: maximum number of argv
 *
 * Return: argc, number of argv parsed, 0 on error
 */
static int pt_parse_args(char *str, char **argv, int max_argc)
{
	int argc = 0;
	char c;

	while (argc < max_argc) {
		while ((c = *str)) {
			if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
				break;
			str++;
		}

		if (*str == '\0')
			break;

		argv[argc++] = str;

		while ((c = *str)) {
			if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
				break;
			str++;
		}

		*str = '\0';
		str++;
	}

	return argc;
}

/**
 * pt_add_match_type - add idr mapping of match type description
 *
 * @pt: packet trace config
 * @name: string name of match type
 * @id: idr index
 *
 * Return: true if idr successfully added, otherwise false
 */
static bool pt_add_match_type(struct packet_trace *pt,
			      const char *name, u8 *id)
{
	int mid;
	unsigned long flags;
	struct pt_match_type *match_type;

	match_type = kzalloc(sizeof(*match_type), GFP_KERNEL);
	if (!match_type)
		return false;
	strncpy(match_type->name, name, PT_MATCH_TYPE_NAME_MAX_SZ);

	spin_lock_irqsave(&pt->match_type_lock, flags);
	mid = idr_alloc(&pt->match_types, match_type, 1, 0x100, GFP_ATOMIC);
	spin_unlock_irqrestore(&pt->match_type_lock, flags);

	if (mid < 0) {
		kfree(match_type);
		return false;
	}

	*id = mid;

	return true;
}

/**
 * pt_remove_match_type - remove idr mapping of match type description
 *
 * @pt: packet trace config
 * @id: idr index to remove
 */
static void pt_remove_match_type(struct packet_trace *pt, u8 id)
{
	unsigned long flags;
	struct pt_match_type *match_type;

	spin_lock_irqsave(&pt->match_type_lock, flags);
	match_type = idr_find(&pt->match_types, id);
	if (match_type)
		idr_remove(&pt->match_types, id);
	spin_unlock_irqrestore(&pt->match_type_lock, flags);

	kfree(match_type);
}

/**
 * pt_free_match_types - idr clean up function
 */
static int pt_free_match_types(int id, void *p, void *data)
{
	kfree(p);
	return 0;
}

/* string name of MGMT subtypes */
static const char *pt_mtype_str[16] = {
	"ASSOC_REQ",
	"ASSOC_RESP",
	"REASSOC_REQ",
	"REASSOC_RESP",
	"PROBE_REQ",
	"PROBE_RESP",
	"TIMING_ADV",
	"Rsvd 7",
	"BEACON",
	"ATIM",
	"DISASSOC",
	"AUTH",
	"DEAUTH",
	"ACTION",
	"ACTION_NOACK",
	"Rsvd F"
};

/**
 * pt_ftype_aton - find index of predefine frame type by name
 *
 * @pt: packet trace config
 * @name: name of predefined frame type
 *
 * Return: frame type index on success, MAC80211_PT_MAX_FTYPES on error
 */
static int pt_ftype_aton(struct packet_trace *pt, const char *name)
{
	int i = 0;

	while (i < MAC80211_PT_MAX_FTYPES && pt->ftypes[i].handler) {
		if (!strcasecmp(name, pt->ftypes[i].name))
			return i;
		i++;
	}

	return MAC80211_PT_MAX_FTYPES;
}

/**
 * pt_install_ftype_handler - install predefined frame type handler
 *
 * @pt: packet trace config
 * @name: frame type name
 * @handler: handler
 * @enable: default enable state
 */
static void pt_install_ftype_handler(struct packet_trace *pt,
				     const char *name,
				     ftype_handler handler,
				     bool enable)
{
	struct ftype_def *pftype;
	int index;
	u8 id;

	if (pt->num_ftypes == MAC80211_PT_MAX_FTYPES)
		return;

	index = pt_ftype_aton(pt, name);

	if (index < MAC80211_PT_MAX_FTYPES)
		return;

	if (pt_add_match_type(pt, name, &id)) {
		pftype = &pt->ftypes[pt->num_ftypes];
		pt->num_ftypes++;

		strncpy(pftype->name, name, PT_MATCH_TYPE_NAME_MAX_SZ);
		pftype->name[PT_MATCH_TYPE_NAME_MAX_SZ] = '\0';
		pftype->handler = handler;
		pftype->enable = enable;
		pftype->id = id;
	}
}

/**
 * pt_check_hdr_len - get ieee80211 header length
 *
 * @skb: ieee80211 frame
 *
 * Return: 24 for non-QoS frame, 26 for QoS frame, 0 for other cases
 */
static inline int pt_check_hdr_len(struct sk_buff *skb)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	int hdr_len;

	if (ieee80211_has_a4(fc))
		return 0;

	if (ieee80211_is_data_qos(fc))
		hdr_len = 26;
	else
		hdr_len = 24;

	if (skb->len <= hdr_len)
		return 0;

	return hdr_len;
}

/**
 * pt_check_etype - check if skb matches ether type
 *
 * @skb: ieee80211 frame
 * @etype: ether type in CPU endian
 *
 * Return: true on match, false otherwise
 */
static inline bool pt_check_etype(struct sk_buff *skb, u16 etype)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	int hdr_len;
	u16 skb_etype;

	if (!ieee80211_is_data(fc))
		return 0;

	hdr_len = pt_check_hdr_len(skb);

	if (hdr_len) {
		if (skb->len < hdr_len + 8)
			return false;

		skb_etype = be16_to_cpu(*(__be16 *)&skb->data[hdr_len + 6]);
		if (skb_etype == etype)
			return true;
	}

	return false;
}

/**
 * pt_check_all_etypes - check if skb matches all configured ether type
 *
 * @pt: packet trace config
 * @skb: ieee80211 frame
 * @id: if matched, set to index of configured entry
 *
 * Return: true on match, false otherwise
 */
static inline bool pt_check_all_etypes(struct packet_trace *pt,
				       struct sk_buff *skb,
				       u8 *id)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	int hdr_len;
	u16 skb_etype;
	int i;

	if (!ieee80211_is_data(fc))
		return 0;

	hdr_len = pt_check_hdr_len(skb);

	if (hdr_len) {
		if (skb->len < hdr_len + 8)
			return false;

		skb_etype = be16_to_cpu(*(__be16 *)&skb->data[hdr_len + 6]);

		spin_lock(&pt->match_config_lock);
		for (i = 0; i < MAC80211_PT_MAX_ETYPES; i++) {
			if (pt->etypes[i] && (pt->etypes[i] == skb_etype)) {
				*id = pt->etypes_id[i];
				spin_unlock(&pt->match_config_lock);
				return true;
			}
		}
		spin_unlock(&pt->match_config_lock);
	}

	return false;
}

/**
 * pt_check_arp - predefined ARP frame handler
 *
 * @pt: packet trace config
 * @skb: ieee80211 frame
 * @tx: true for TX, false for RX
 *
 * Return: true on match, false otherwise
 */
static inline bool pt_check_arp(struct packet_trace *pt,
				struct sk_buff *skb,
				bool tx)
{
	return pt_check_etype(skb, ETH_P_ARP); /* 0x0806 */
}

/**
 * pt_check_eapol - predefined EAPOL frame handler
 *
 * @pt: packet trace config
 * @skb: ieee80211 frame
 * @tx: true for TX, false for RX
 *
 * Return: true on match, false otherwise
 */
static inline bool pt_check_eapol(struct packet_trace *pt,
				  struct sk_buff *skb,
				  bool tx)
{
	return pt_check_etype(skb, ETH_P_PAE); /* 0x888E */
}

/* bootp_pktstructure and recv validation of BOOTP/DHCP frame is
 * borrowed from net/ipv4/ipconfig.c
 */
struct bootp_pkt {		/* BOOTP packet format */
	struct iphdr iph;	/* IP header */
	struct udphdr udph;	/* UDP header */
	u8 op;			/* 1=request, 2=reply */
	u8 htype;		/* HW address type */
	u8 hlen;		/* HW address length */
	u8 hops;		/* Used only by gateways */
	__be32 xid;		/* Transaction ID */
	__be16 secs;		/* Seconds since we started */
	__be16 flags;		/* Just what it says */
	__be32 client_ip;	/* Client's IP address if known */
	__be32 your_ip;		/* Assigned IP address */
	__be32 server_ip;	/* (Next, e.g. NFS) Server's IP address */
	__be32 relay_ip;	/* IP address of BOOTP relay */
	u8 hw_addr[16];		/* Client's HW address */
	u8 serv_name[64];	/* Server host name */
	u8 boot_file[128];	/* Name of boot file */
	u8 exten[312];		/* DHCP options / BOOTP vendor extensions */
};

#define DHCP_SERVER_PORT	67
#define DHCP_CLIENT_PORT	68

/**
 * pt_check_dhcp - predefined DHCP frame handler
 *
 * @pt: packet trace config
 * @skb: ieee80211 frame
 * @tx: true for TX, false for RX
 *
 * Return: true on match, false otherwise
 */
static inline bool pt_check_dhcp(struct packet_trace *pt,
				 struct sk_buff *skb,
				 bool tx)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	int hdr_len;
	int etype;
	struct bootp_pkt *b;
	struct iphdr *h;

	if (!ieee80211_is_data(fc))
		return 0;

	hdr_len = pt_check_hdr_len(skb);

	if (!hdr_len)
		return false;

	b = (struct bootp_pkt *)&skb->data[hdr_len + 8];
	h = &b->iph;

	if (skb->len < hdr_len + 8 + sizeof(*b) - sizeof(b->exten))
		return false;

	etype = (skb->data[hdr_len + 6] << 8) + skb->data[hdr_len + 7];

	if (etype != ETH_P_IP ||
	    h->version != 4 ||
	    h->ihl != 5 ||
	    h->protocol != IPPROTO_UDP ||
	    ip_is_fragment(h) ||
	    skb->len < ntohs(h->tot_len) + hdr_len + 8 ||
	    ip_fast_csum((char *)h, h->ihl) ||
	    ntohs(h->tot_len) < ntohs(b->udph.len) + sizeof(struct iphdr) ||
	    (tx && b->udph.source != htons(DHCP_SERVER_PORT) &&
	     b->udph.dest != htons(DHCP_CLIENT_PORT)) ||
	    (!tx && b->udph.source != htons(DHCP_CLIENT_PORT) &&
	     b->udph.dest != htons(DHCP_SERVER_PORT)))
		return false;

	return true;
}

/**
 * pt_check_all_ftypes - check all predefined handlers
 *
 * @pt: packet trace config
 * @skb: ieee80211 frame
 * @id: if matched, set to index of configured entry
 *
 * Return: true on match, false otherwise
 */
static inline bool pt_check_all_ftypes(struct packet_trace *pt,
				       struct sk_buff *skb,
				       bool tx,
				       u8 *id)
{
	int i;

	spin_lock(&pt->match_config_lock);
	for (i = 0; i < MAC80211_PT_MAX_FTYPES; i++) {
		if (pt->ftypes[i].handler &&
		    pt->ftypes[i].enable &&
		    pt->ftypes[i].handler(pt, skb, tx)) {
			*id = pt->ftypes[i].id;
			spin_unlock(&pt->match_config_lock);
			return true;
		}
	}
	spin_unlock(&pt->match_config_lock);

	return false;
}

/**
 * pt_set_mgmt_stype - enable or disable MGMT subtype
 *
 * @pt: packet trace config
 * @stype: MGMT subtype index, 0~15
 * @allowed: add or remove
 */
static void pt_set_mgmt_stype(struct packet_trace *pt, int stype,
			      bool allowed)
{
	stype &= 0x0F;
	if (pt->allowed_mgmt_stypes & BIT(stype)) {
		if (allowed)
			pt->traced_mgmt_stypes |= BIT(stype);
		else
			pt->traced_mgmt_stypes &= ~BIT(stype);
	}
}

/**
 * pt_check_mgmt_stype - check all enabled MGMT subtypes
 *
 * @pt: packet trace config
 * @skb: ieee80211 frame
 * @id: if matched, set to index of configured entry
 *
 * Return: true on match, false otherwise
 */
static inline int pt_check_mgmt_stype(struct packet_trace *pt,
				      struct sk_buff *skb,
				      u8 *id)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	bool match = false;

	if (ieee80211_is_mgmt(fc)) {
		u16 stype = (le16_to_cpu(fc) & IEEE80211_FCTL_STYPE) >> 4;
		*id = stype & 0x0F;
		spin_lock(&pt->match_config_lock);
		match = BIT(stype & 0x0F) & pt->traced_mgmt_stypes;
		spin_unlock(&pt->match_config_lock);
	}

	return match;
}

/**
 * pt_mac_traceable - check if MAC address should be traced
 *
 * @pt: packet trace config
 * @addr: MAC address
 *
 * Return: true on match, false otherwise
 */
static inline bool pt_mac_traceable(struct packet_trace *pt, u8 *addr)
{
	struct sta_def *p, *n;

	spin_lock(&pt->match_station_lock);
	list_for_each_entry_safe(p, n, &pt->station_list, list) {
		if (ether_addr_equal(p->addr, addr)) {
			spin_unlock(&pt->match_station_lock);
			return true;
		}
	}
	spin_unlock(&pt->match_station_lock);

	return false;
}

/**
 * pt_get_token - get tracing roken
 *
 * @pt: packet trace config
 * @tx: true for TX, false for RX
 *
 * Return: non-zero u16 token
 */
static inline u16 pt_get_token(struct packet_trace *pt, bool tx)
{
	u16 token;

	if (tx) {
		pt->tx_token_counter++;

		if (pt->tx_token_counter == 0)
			pt->tx_token_counter++;

		token = pt->tx_token_counter;
	} else {
		pt->rx_token_counter++;

		if (pt->rx_token_counter == 0)
			pt->rx_token_counter++;

		token = pt->rx_token_counter;
	}

	return token;
}

/**
 * ptctrl_show - show current packet trace configuration
 *
 * @seq: seq file pointer
 * @v: private
 *
 * Return: always return 0
 */
static int ptctrl_show(struct seq_file *seq, void *v)
{
	struct ieee80211_local *local = seq->private;
	struct packet_trace *pt = local->pt_config;
	int i, j;
	struct sta_def *p, *n;

	seq_printf(seq, "Packet trace debug is %s\n",
		   local->pt_enable ? "enabled" : "disabled");

	seq_puts(seq, "Packet trace debug settings\n");

	spin_lock(&pt->match_config_lock);
	seq_printf(seq, "\nPredefined frame types: [%d/%d]\n",
		   pt->num_ftypes, MAC80211_PT_MAX_FTYPES);
	for (i = 0; i < MAC80211_PT_MAX_FTYPES; i++) {
		if (pt->ftypes[i].handler)
			seq_printf(seq, "  %s : %s\n", pt->ftypes[i].name,
				   pt->ftypes[i].enable ?
				   "enabled" : "disabled");
	}

	seq_puts(seq, "\n802.11 MGMT Subtypes:\n");
	for (i = 0; i < MAC80211_PT_MAX_STYPES; i++) {
		if (BIT(i & 0x0F) & pt->traced_mgmt_stypes)
			seq_printf(seq, "  %s\n", pt_mtype_str[i]);
	}

	seq_printf(seq, "\nEther Types: [%d/%d]\n",
		   pt->num_etypes, MAC80211_PT_MAX_ETYPES);
	for (i = 0; i < MAC80211_PT_MAX_ETYPES; i++) {
		if (pt->etypes[i])
			seq_printf(seq, "  0x%04x\n", pt->etypes[i]);
	}
	spin_unlock(&pt->match_config_lock);

	j = 1;
	spin_lock(&pt->match_station_lock);
	seq_printf(seq, "\nStation MAC addresses: [%d]\n", pt->num_stations);
	list_for_each_entry_safe(p, n, &pt->station_list, list) {
		seq_printf(seq, "[%2d] %pM\n", j++, p->addr);
	}
	spin_unlock(&pt->match_station_lock);

	return 0;
}

static int pt_ftype_cmd_handler(struct packet_trace *pt,
				int argc, char **argv, bool add)
{
	int i;

	if (argc < 2)
		return -EINVAL;

	for (i = 0; i < MAC80211_PT_MAX_FTYPES; i++) {
		if (pt->ftypes[i].handler &&
		    !strcmp(argv[1], pt->ftypes[i].name)) {
			spin_lock(&pt->match_config_lock);
			pt->ftypes[i].enable = add;
			spin_unlock(&pt->match_config_lock);

			return PT_CMD_STATUS_HANDLED;
		}
	}

	return PT_CMD_STATUS_NOOP;
}

static int pt_mgmt_cmd_handler(struct packet_trace *pt,
			       int argc, char **argv, bool add)
{
	unsigned long num;

	if (argc < 3)
		return -EINVAL;

	if (kstrtoul(argv[2], 0, &num))
		return -EINVAL;

	if (num >= MAC80211_PT_MAX_STYPES)
		return -EINVAL;

	spin_lock(&pt->match_config_lock);
	pt_set_mgmt_stype(pt, num, add);
	spin_unlock(&pt->match_config_lock);

	return PT_CMD_STATUS_HANDLED;
}

static int pt_ether_cmd_handler(struct packet_trace *pt,
				int argc, char **argv, bool add)
{
	unsigned long num;
	u8 id;
	int i;

	if (argc < 3)
		return -EINVAL;

	if (kstrtoul(argv[2], 0, &num))
		return -EINVAL;

	if (num < ETH_P_802_3_MIN || num > 0xFFFF)
		return -EINVAL;

	spin_lock(&pt->match_config_lock);

	for (i = 0; i < MAC80211_PT_MAX_ETYPES; i++) {
		if (pt->etypes[i] && pt->etypes[i] == num) {
			if (!add) {
				pt->etypes[i] = 0;
				pt->num_etypes--;
				pt_remove_match_type(pt, pt->etypes_id[i]);
			}
			spin_unlock(&pt->match_config_lock);

			return PT_CMD_STATUS_HANDLED;
		}
	}

	if (add) {
		for (i = 0; i < MAC80211_PT_MAX_ETYPES; i++) {
			if (!pt->etypes[i]) {
				if (pt_add_match_type(pt, argv[2], &id)) {
					pt->etypes[i] = num;
					pt->etypes_id[i] = id;
					pt->num_etypes++;
				}
				break;
			}
		}
	}
	spin_unlock(&pt->match_config_lock);

	return PT_CMD_STATUS_HANDLED;
}

static int pt_sta_cmd_handler(struct packet_trace *pt,
			      int argc, char **argv, bool add)
{
	u8 mac_addr[ETH_ALEN];
	struct sta_def *p, *n;

	if (argc < 3)
		return -EINVAL;

	if (pt_parse_mac(argv[2], mac_addr) == -1)
		return -EINVAL;

	spin_lock(&pt->match_station_lock);
	list_for_each_entry_safe(p, n, &pt->station_list, list) {
		if (ether_addr_equal(p->addr, mac_addr)) {
			if (!add) {
				list_del(&p->list);
				pt->num_stations--;
				spin_unlock(&pt->match_station_lock);
				kfree(p);
				goto log_sta_op;
			}

			spin_unlock(&pt->match_station_lock);
			return PT_CMD_STATUS_HANDLED;
		}
	}
	spin_unlock(&pt->match_station_lock);

	if (add) {
		p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;

		ether_addr_copy(p->addr, mac_addr);
		spin_lock(&pt->match_station_lock);
		list_add_tail(&p->list, &pt->station_list);
		pt->num_stations++;
		spin_unlock(&pt->match_station_lock);
	}

log_sta_op:
	if (pt->flags & PT_F_LOG_STA_CTL_CMD) {
		PT_LOG_INTERNAL("packet trace: MAC %pM %s\n",
				mac_addr, add ? "added" : "removed");
	}

	return PT_CMD_STATUS_HANDLED;
}

static int pt_all_sta_cmd_handler(struct packet_trace *pt,
				  int argc, char **argv, bool add)
{
	struct sta_def *p, *n;

	/* only "rem all-sta" */
	if (argc < 2 || add)
		return -EINVAL;

	spin_lock(&pt->match_station_lock);
	list_for_each_entry_safe(p, n, &pt->station_list, list) {
		list_del(&p->list);
		spin_unlock(&pt->match_station_lock);
		kfree(p);
		if (pt->flags & PT_F_LOG_STA_CTL_CMD) {
			PT_LOG_INTERNAL("packet trace: MAC %pM removed\n",
					p->addr);
		}
		spin_lock(&pt->match_station_lock);
	}
	spin_unlock(&pt->match_station_lock);
	pt->num_stations = 0;

	return PT_CMD_STATUS_HANDLED;
}

/**
 * ptctrl_write - parse command and configure packet trace
 *
 * @file: file pointer
 * @buf: user space buffer
 * @count: size of buffer
 * @ppos: file position
 *
 * Return: count of input consumed, negative values on error
 */
static ssize_t ptctrl_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct seq_file *seq = file->private_data;
	struct ieee80211_local *local = seq->private;
	struct packet_trace *pt = local->pt_config;
	char data[PT_MAX_INPUT_SZ];
	char *argv[PT_MAX_ARGC];
	int argc;
	int ret;
	bool add = true;

#define CALL_CMDH(cmdh)					\
	do {						\
		ret = pt_##cmdh##_cmd_handler(pt, argc, argv, add);	\
		if (ret == PT_CMD_STATUS_HANDLED)	\
			return count;			\
		if (ret == PT_CMD_STATUS_NOOP)		\
			break;				\
		return ret;				\
	} while (0)

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (count <= 1)
		return -EINVAL;

	if (count >= sizeof(data))
		count = sizeof(data) - 1;

	if (copy_from_user(data, buf, count))
		return -EFAULT;

	data[count] = '\0';

	argc = pt_parse_args(data, argv, PT_MAX_ARGC);

	if (argc < 2)
		return -EINVAL;

	if (!strcmp(argv[0], "add"))
		add = true;
	else if (!strcmp(argv[0], "rem"))
		add = false;
	else
		return -EINVAL;

	CALL_CMDH(ftype);

	if (!strcmp(argv[1], "mgmt"))
		CALL_CMDH(mgmt);

	if (!strcmp(argv[1], "ether"))
		CALL_CMDH(ether);

	if (!strcmp(argv[1], "sta"))
		CALL_CMDH(sta);

	if (!strcmp(argv[1], "all-sta"))
		CALL_CMDH(all_sta);

#undef CALL_CMDH

	return -EINVAL;
}

static int ptctrl_open(struct inode *inode, struct file *file)
{
	return single_open(file, ptctrl_show, inode->i_private);
}

static const struct file_operations ptctrl_ops = {
	.owner   = THIS_MODULE,
	.open    = ptctrl_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = ptctrl_write,
	.release = single_release,
};

/**
 * pt_add_debugfs - add packet trace debugfs entries
 *
 * @local: ieee80211_local pointing to hw
 */
static void pt_add_debugfs(struct ieee80211_local *local)
{
	struct packet_trace *pt = local->pt_config;
	struct dentry *phyd = local->hw.wiphy->debugfsdir;
	struct dentry *ptd;

	if (!phyd)
		return;

	ptd = debugfs_create_dir("packet_trace", phyd);
	pt->debugfsdir = ptd;

	if (!ptd)
		return;

	debugfs_create_bool("ptenable", S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP,
			    ptd, &local->pt_enable);
	debugfs_create_file("ptctrl", S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP,
			    ptd, local, &ptctrl_ops);
}

static bool pt_sprintf_cookie_info(struct ieee80211_local *local,
				   char *s, size_t max_len,
				   struct packet_trace_cookie *cookie)
{
	struct packet_trace *pt = local->pt_config;
	unsigned long flags;
	struct pt_match_type *match_type;

	if (cookie->flags & PT_F_TRACE_MGMT) {
		if (pt->traced_mgmt_stypes & BIT(cookie->id & 0x0F))
			snprintf(s, max_len, "MGMT %s",
				 pt_mtype_str[cookie->id & 0x0F]);
		else
			return false;
	} else if (cookie->flags &
		   (PT_F_TRACE_ETHERTYPE | PT_F_TRACE_FRAMETYPE)) {
		spin_lock_irqsave(&pt->match_type_lock, flags);
		match_type = idr_find(&pt->match_types, cookie->id);
		if (match_type)
			snprintf(s, max_len, "%s", match_type->name);
		spin_unlock_irqrestore(&pt->match_type_lock, flags);
		if (!match_type)
			return false;
	} else {
		return false;
	}

	if (pt->flags & PT_F_LOG_PRINT_TOKEN) {
		int len = strlen(s);

		max_len -= len;
		/* print only with enough space, " (5 digits)" + NUL */
		if (max_len >= 9)
			snprintf(s + len, max_len, "(%u)", cookie->token);
	}

	return true;
}

/* Export APIs */

int packet_trace_init(struct ieee80211_local *local)
{
	struct packet_trace *pt;

	local->pt_config = kzalloc(sizeof(*pt), GFP_KERNEL);
	if (!local->pt_config)
		return -ENOMEM;

	pt = local->pt_config;
	pt->local = local;

	idr_init(&pt->match_types);
	spin_lock_init(&pt->match_type_lock);
	spin_lock_init(&pt->match_config_lock);
	spin_lock_init(&pt->match_station_lock);
	INIT_LIST_HEAD(&pt->station_list);

	/* PT_F_LOG_PRINT_SUCCESS is for debug only */
	pt->flags = PT_F_LOG_STA_CTL_CMD |
		PT_F_LOG_WHEN_TAGGED |
		PT_F_LOG_PRINT_TOKEN;

	/* Install handlers for perdefined frame type checks */
	pt_install_ftype_handler(pt, "arp", pt_check_arp, true);
	pt_install_ftype_handler(pt, "dhcp", pt_check_dhcp, true);
	pt_install_ftype_handler(pt, "eapol", pt_check_eapol, false);

	/* Set trace-able MGMT STYPEs */
	pt->allowed_mgmt_stypes = 0x1C0F;
	pt->traced_mgmt_stypes = 0;

	pt_add_debugfs(local);

	if (pt->flags & PT_F_LOG_STA_CTL_CMD) {
		PT_LOG_INTERNAL("packet trace: [%s] initialized\n",
				wiphy_name(local->hw.wiphy));
	}

	return 0;
}
EXPORT_SYMBOL(packet_trace_init);

void packet_trace_deinit(struct ieee80211_local *local)
{
	struct packet_trace *pt = local->pt_config;
	struct sta_def *p, *n;

	if (pt) {
		debugfs_remove_recursive(pt->debugfsdir);

		spin_lock(&pt->match_station_lock);
		list_for_each_entry_safe(p, n, &pt->station_list, list) {
			list_del(&p->list);
			spin_unlock(&pt->match_station_lock);
			kfree(p);
			spin_lock(&pt->match_station_lock);
		}
		spin_unlock(&pt->match_station_lock);

		idr_for_each(&pt->match_types, pt_free_match_types, NULL);
		idr_destroy(&pt->match_types);

		kfree(pt);
		local->pt_config = NULL;
	}
}
EXPORT_SYMBOL(packet_trace_deinit);

void packet_trace_set_tx_info(struct ieee80211_local *local,
			      struct sta_info *sta,
			      struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct packet_trace *pt = local->pt_config;
	struct packet_trace_cookie *cookie;
	struct ieee80211_hdr *hdr = (void *)skb->data;
	u8 id;
	u8 *addr;
	const char *dev_name;
	char cookie_str[PT_LOG_COOKIE_STR_MAX_SZ];

	info->pt_cookie = 0;

	if (!IS_ERR_OR_NULL(sta)) {
		addr = sta->addr;
		dev_name = sta->sdata->name;
	} else {
		addr = hdr->addr1;
		dev_name = wiphy_name(local->hw.wiphy);
	}
	if (!pt_mac_traceable(pt, addr))
		return;

	cookie = (struct packet_trace_cookie *)&info->pt_cookie;

	if (pt_check_mgmt_stype(pt, skb, &id))
		cookie->flags = PT_F_TRACE_MGMT;
	else if (pt_check_all_etypes(pt, skb, &id))
		cookie->flags = PT_F_TRACE_ETHERTYPE;
	else if (pt_check_all_ftypes(pt, skb, true, &id))
		cookie->flags = PT_F_TRACE_FRAMETYPE;

	if (!cookie->flags)
		return;

	cookie->id = id;
	cookie->token = pt_get_token(pt, true);

	if (!(pt->flags & PT_F_LOG_WHEN_TAGGED))
		return;

	if (!pt_sprintf_cookie_info(local, cookie_str,
				    PT_LOG_COOKIE_STR_MAX_SZ, cookie))
		cookie_str[0] = '\0';

	PT_LOG_INTERNAL("%s: STA %pM TX %s traced\n",
			dev_name, addr, cookie_str);
}
EXPORT_SYMBOL(packet_trace_set_tx_info);

void packet_trace_set_rx_status(struct ieee80211_local *local,
				struct sta_info *sta,
				struct sk_buff *skb)
{
	struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
	struct packet_trace *pt = local->pt_config;
	struct packet_trace_cookie *cookie;
	struct ieee80211_hdr *hdr = (void *)skb->data;
	u8 id;
	u8 *addr;
	const char *dev_name;
	u16 sn;
	char cookie_str[PT_LOG_COOKIE_STR_MAX_SZ];

	status->pt_cookie = 0;

	if (!IS_ERR_OR_NULL(sta)) {
		addr = sta->addr;
		dev_name = sta->sdata->name;
	} else {
		addr = hdr->addr2;
		dev_name = wiphy_name(local->hw.wiphy);
	}
	if (!pt_mac_traceable(pt, addr))
		return;

	cookie = (struct packet_trace_cookie *)&status->pt_cookie;

	if (pt_check_mgmt_stype(pt, skb, &id))
		cookie->flags = PT_F_TRACE_MGMT;
	else if (pt_check_all_etypes(pt, skb, &id))
		cookie->flags = PT_F_TRACE_ETHERTYPE;
	else if (pt_check_all_ftypes(pt, skb, false, &id))
		cookie->flags = PT_F_TRACE_FRAMETYPE;

	if (!cookie->flags)
		return;

	cookie->id = id;
	cookie->token = pt_get_token(pt, false);

	if (!(pt->flags & PT_F_LOG_WHEN_TAGGED))
		return;

	if (!pt_sprintf_cookie_info(local, cookie_str,
				    PT_LOG_COOKIE_STR_MAX_SZ, cookie))
		cookie_str[0] = '\0';

	sn = (__le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ) >> 4;
	PT_LOG_INTERNAL("%s: STA %pM RX %s RSSI=%d SN=%d traced\n",
			dev_name, addr, cookie_str, status->signal, sn);
}
EXPORT_SYMBOL(packet_trace_set_rx_status);

bool packet_trace_tx_skb_traced(struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct packet_trace_cookie *cookie;

	cookie = (struct packet_trace_cookie *)&info->pt_cookie;

	return cookie->flags & PT_F_TRACE;
}
EXPORT_SYMBOL(packet_trace_tx_skb_traced);

bool packet_trace_rx_status_traced(struct sk_buff *skb)
{
	struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
	struct packet_trace_cookie *cookie;

	cookie = (struct packet_trace_cookie *)&status->pt_cookie;

	return cookie->flags & PT_F_TRACE;
}
EXPORT_SYMBOL(packet_trace_rx_status_traced);

void packet_trace_tx_log_dbg(struct ieee80211_local *local,
			     struct sk_buff *skb,
			     ieee80211_tx_result result,
			     const char *driver,
			     const char *fmt, ...)
{
	struct packet_trace *pt = local->pt_config;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct packet_trace_cookie *cookie;
	struct ieee80211_hdr *hdr;
	char cookie_str[PT_LOG_COOKIE_STR_MAX_SZ];
	char prefix[PT_LOG_PREFIX_STR_MAX_SZ];
	u8 *ra;
	u16 sn;
	char *result_str;
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	cookie = (struct packet_trace_cookie *)&info->pt_cookie;
	if (!(cookie->flags & PT_F_TRACE))
		return;

	if (result != TX_DROP) {
		if (!(pt->flags & PT_F_LOG_PRINT_SUCCESS))
			return;
		result_str = (result == TX_CONTINUE) ? "CONTINUE" : "QUEUED";
	} else {
		result_str = "DROP";
	}

	if (!pt_sprintf_cookie_info(local, cookie_str,
				    PT_LOG_COOKIE_STR_MAX_SZ, cookie))
		return;

	hdr = (void *)skb->data;
	ra = hdr->addr1;
	sn = (__le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ) >> 4;
	snprintf(prefix, PT_LOG_PREFIX_STR_MAX_SZ,
		 "%s: STA %pM TX SN=%u: %s - %s",
		 driver, ra, sn, cookie_str, result_str);

	va_start(args, fmt);
	vaf.va = &args;
	pr_debug("%s: %pV\n", prefix, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(packet_trace_tx_log_dbg);

void packet_trace_tx_status_log_dbg(struct ieee80211_local *local,
				    struct sk_buff *skb,
				    const char *driver,
				    const char *fmt, ...)
{
	struct packet_trace *pt = local->pt_config;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct packet_trace_cookie *cookie;
	struct ieee80211_hdr *hdr;
	char cookie_str[PT_LOG_COOKIE_STR_MAX_SZ];
	char prefix[PT_LOG_PREFIX_STR_MAX_SZ];
	bool tx_success;
	/*bool tx_no_ack;*/
	u8 *ra;
	u16 sn;
	char *result_str;
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	cookie = (struct packet_trace_cookie *)&info->pt_cookie;
	if (!(cookie->flags & PT_F_TRACE))
		return;

	tx_success = info->flags & IEEE80211_TX_STAT_NOACK_TRANSMITTED ||
		info->flags & IEEE80211_TX_STAT_ACK;

	if (tx_success) {
		if (!(pt->flags & PT_F_LOG_PRINT_SUCCESS))
			return;
		result_str = "SENT";
	} else {
		result_str = "FAIL";
	}

	if (!pt_sprintf_cookie_info(local, cookie_str,
				    PT_LOG_COOKIE_STR_MAX_SZ, cookie))
		return;

	hdr = (void *)skb->data;
	ra = hdr->addr1;
	sn = (__le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ) >> 4;
		snprintf(prefix, PT_LOG_PREFIX_STR_MAX_SZ,
			 "%s: STA %pM TX SN=%u: %s - %s",
			 driver, ra, sn, cookie_str, result_str);

	va_start(args, fmt);
	vaf.va = &args;
	pr_debug("%s: %pV\n", prefix, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(packet_trace_tx_status_log_dbg);

void packet_trace_rx_status_log_dbg(struct ieee80211_local *local,
				    struct sk_buff *skb,
				    ieee80211_rx_result result,
				    const char *driver,
				    const char *fmt, ...)
{
	struct packet_trace *pt = local->pt_config;
	struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
	struct packet_trace_cookie *cookie;
	struct ieee80211_hdr *hdr;
	char cookie_str[PT_LOG_COOKIE_STR_MAX_SZ];
	char prefix[PT_LOG_PREFIX_STR_MAX_SZ];
	u8 *ta;
	u16 sn;
	char *result_str;
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	cookie = (struct packet_trace_cookie *)&status->pt_cookie;
	if (!(cookie->flags & PT_F_TRACE))
		return;

	if (result == RX_CONTINUE || result == RX_QUEUED) {
		if (!(pt->flags & PT_F_LOG_PRINT_SUCCESS))
			return;
		result_str = (result == RX_CONTINUE) ? "CONTINUE" : "QUEUED";
	} else {
		result_str = "DROP";
	}

	if (!pt_sprintf_cookie_info(local, cookie_str,
				    PT_LOG_COOKIE_STR_MAX_SZ, cookie))
		return;

	hdr = (void *)skb->data;
	ta = hdr->addr2;
	sn = (__le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ) >> 4;
	snprintf(prefix, PT_LOG_PREFIX_STR_MAX_SZ,
		 "%s: STA %pM RX RSSI=%d SN=%u: %s - %s",
		 driver, ta, status->signal, sn, cookie_str, result_str);

	va_start(args, fmt);
	vaf.va = &args;
	pr_debug("%s: %pV\n", prefix, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(packet_trace_rx_status_log_dbg);

