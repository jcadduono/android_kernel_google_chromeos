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
#include "wifi_diag.h"

struct wifi_diag;

#define F_IS_FRAMETYPE		BIT(0)
#define F_IS_ETHERTYPE		BIT(1)
#define F_IS_MGMT		BIT(2)
#define F_IS_MARKED		(BIT(0) | BIT(1) | BIT(2))

/**
 * struct wifi_diag cookie - structure carrying wifi diagnostic tagging
 * information. It's set at TX and RX flow entrance and will be used by
 * subsequent logging calls.
 *
 * @flags: tracing flags
 * @id: information used for logging output
 * @token: used to follow packet and matching TX status
 */
struct wifi_diag_cookie {
	u32 flags : 8;
	u32 id    : 8;
	u32 token : 16;
} __packed;

#define MAX_FTYPES		8
#define MAX_STYPES		16
#define MAX_ETYPES		8
#define MAX_STATIONS		32

/* function prototype to match frame types */
typedef bool (*ftype_handler)(struct wifi_diag *cfg, struct sk_buff *skb);

/* function prototype to decode more frame information */
typedef int (*ftype_sprintf)(struct sk_buff *skb, char *buf, size_t size);

#define MATCH_TYPE_DESCR_SZ	16

/**
 * struct ftype_def - predefined frame type handlers
 *
 * @enable: true if valid
 * @name: frame type name
 * @handler: frame type handler
 */
struct ftype_def {
	bool enable;
	char name[MATCH_TYPE_DESCR_SZ];
	ftype_handler handler;
	ftype_sprintf get_info;
	u8 id;
};

/**
 * struct match_type - match type description
 *
 * @descr: match type string description
 */
struct match_type {
	struct ftype_def *ftype;
	u16 etype;
};

/**
 * struct sta_def - stations under diagnostic
 *
 * @addr: MAC address of station
 */
struct sta_def {
	struct list_head list;
	u8 addr[ETH_ALEN];
};

/**
 * struct wifi_diag - wifi diagnostic configuration per each phy interface
 *
 * @flags: global flags
 * @tx_token_counter: tx token generator
 * @rx_token_counter: rx token generator
 * @num_ftypes: number of predefined frame types initialized
 * @ftypes: predefined frame type definiftions
 * @allowed_mgmt_stypes: MGMT subtypes supported by wifi_diag
 * @enabled_mgmt_stypes: MGMT subtypes enabled to be diagnosed
 * @num_etypes: number of ether types configured
 * @etypes: ether type configuration
 * @num_stations: number of stations configured
 * @stations: station MAC address configuration
 * @local: save the struct ieee80211_local pointer
 */
struct wifi_diag {
	u32 flags;
	u16 tx_token_counter;
	u16 rx_token_counter;

	/* prevents concurrent debugfs configuration */
	struct mutex config_mtx;

	struct idr match_types;
	/* protect match type description lookup idr */
	spinlock_t match_type_lock;

	/* protects packet match configuration */
	spinlock_t config_lock;

	/* frame type handlers */
	int num_ftypes;
	struct ftype_def ftypes[MAX_FTYPES];

	/* 802.11 MGMT STYPEs bitmask */
	u16 allowed_mgmt_stypes;
	u16 enabled_mgmt_stypes;

	/* ether_types */
	int num_etypes;
	u16 etypes[MAX_ETYPES];
	u8 etypes_id[MAX_ETYPES];

	/* protects configure and lookup of station_list */
	spinlock_t station_lock;
	int num_stations;
	struct list_head station_list;

	struct dentry *debugfsdir;
	void *local;
};

#define WD_LOG_INTERNAL(fmt, ...) pr_debug(fmt, ##__VA_ARGS__)
#define WD_LOG_TXRX(fmt, ...) pr_info(fmt, ##__VA_ARGS__)

#define LOG_COOKIE_STR_SZ	48
#define LOG_PREFIX_STR_SZ	128

#define DEBUGFS_MAX_INPUT_SZ	128
#define DEBUGFS_MAX_ARGC	3

#define CMD_STATUS_HANDLED	0
#define CMD_STATUS_NOOP		1

/**
 * parse_mac - parse string into MAC address
 *
 * @str: MAC address string, in format of "aa:bb:cc:dd:ee:ff"
 * @addr: parsed MAC address
 *
 * Return: 0 on success, -1 on error
 */
static int parse_mac(char *str, u8 *addr)
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
 * parse_args - parse input string into argc count and argv array
 *
 * @str: input command string
 * @argv: parsed string segments
 * @max_argc: maximum number of argv
 *
 * Return: argc, number of argv parsed, 0 on error
 */
static int parse_args(char *str, char **argv, int max_argc)
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
 * add_match_type - add idr mapping of match type description
 *
 * @cfg: wifi diag configuration
 * @descr: description of match type
 * @id: idr index
 *
 * Return: true if idr successfully added, otherwise false
 */
static bool add_match_type(struct wifi_diag *cfg,
			   struct ftype_def *ftype,
			   u16 etype, u8 *id)
{
	int mid;
	struct match_type *match;

	match = kzalloc(sizeof(*match), GFP_KERNEL);
	if (!match)
		return false;
	match->ftype = ftype;
	match->etype = etype;

	spin_lock_bh(&cfg->match_type_lock);
	mid = idr_alloc(&cfg->match_types, match, 1, 0x100, GFP_ATOMIC);
	spin_unlock_bh(&cfg->match_type_lock);

	if (mid < 0) {
		kfree(match);
		return false;
	}

	*id = mid;

	return true;
}

/**
 * remove_match_type - remove idr mapping of match type description
 *
 * @cfg: wifi diag configuration
 * @id: idr index to remove
 */
static void remove_match_type(struct wifi_diag *cfg, u8 id)
{
	struct match_type *match;

	spin_lock_bh(&cfg->match_type_lock);
	match = idr_find(&cfg->match_types, id);
	if (match)
		idr_remove(&cfg->match_types, id);
	spin_unlock_bh(&cfg->match_type_lock);

	kfree(match);
}

/**
 * free_match_types - idr clean up function
 */
static int free_match_types(int id, void *p, void *data)
{
	kfree(p);
	return 0;
}

/* string name of MGMT subtypes */
static const char *mtype_str[16] = {
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
 * install_ftype_handler - install frame type handler
 *
 * @cfg: wifi diag configuration
 * @name: frame type name
 * @handler: handler callback
 * @get_info: get_info callback
 * @enable: default enable state
 */
static void install_ftype_handler(struct wifi_diag *cfg,
				  const char *name,
				  ftype_handler handler,
				  ftype_sprintf get_info,
				  bool enable)
{
	struct ftype_def *pftype;
	u8 id;

	if (cfg->num_ftypes == MAX_FTYPES)
		return;

	pftype = &cfg->ftypes[cfg->num_ftypes];
	strlcpy(pftype->name, name, MATCH_TYPE_DESCR_SZ);
	pftype->handler = handler;
	pftype->get_info = get_info;

	if (add_match_type(cfg, pftype, 0, &id)) {
		pftype->enable = enable;
		pftype->id = id;
		cfg->num_ftypes++;
	}
}

/**
 * ieee80211_hdr_len - get ieee80211 header length
 *
 * @skb: ieee80211 frame
 *
 * Return: 24 for non-QoS frame, 26 for QoS frame, 0 for other cases
 */
static inline int ieee80211_hdr_len(struct sk_buff *skb)
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

	return hdr_len;
}

/**
 * check_etype - check if skb matches ether type
 *
 * @skb: ieee80211 frame
 * @etype: ether type in CPU endian
 *
 * Return: true on match, false otherwise
 */
static inline bool check_etype(struct sk_buff *skb, u16 etype)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	int hdr_len;
	u16 skb_etype;

	if (!ieee80211_is_data(fc))
		return false;

	hdr_len = ieee80211_hdr_len(skb);

	if (hdr_len && skb->len >= hdr_len + 8) {
		skb_etype = be16_to_cpu(*(__be16 *)&skb->data[hdr_len + 6]);
		if (skb_etype == etype)
			return true;
	}

	return false;
}

/**
 * check_all_etypes - check if skb matches all configured ether type
 *
 * @cfg: wifi diag configuration
 * @skb: ieee80211 frame
 * @id: if matched, set to index of configured entry
 *
 * Return: true on match, false otherwise
 */
static inline bool check_all_etypes(struct wifi_diag *cfg,
				    struct sk_buff *skb,
				    u8 *id)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	int hdr_len;
	u16 skb_etype;
	int i;

	if (!ieee80211_is_data(fc))
		return false;

	hdr_len = ieee80211_hdr_len(skb);

	if (hdr_len && skb->len >= hdr_len + 8) {
		skb_etype = be16_to_cpu(*(__be16 *)&skb->data[hdr_len + 6]);

		spin_lock(&cfg->config_lock);
		for (i = 0; i < MAX_ETYPES; i++) {
			if (cfg->etypes[i] && cfg->etypes[i] == skb_etype) {
				*id = cfg->etypes_id[i];
				spin_unlock(&cfg->config_lock);
				return true;
			}
		}
		spin_unlock(&cfg->config_lock);
	}

	return false;
}

/**
 * check_arp - ARP frame handler
 *
 * @cfg: wifi diag configuration
 * @skb: ieee80211 frame
 *
 * Return: true on match, false otherwise
 */
static bool check_arp(struct wifi_diag *cfg, struct sk_buff *skb)
{
	return check_etype(skb, ETH_P_ARP); /* 0x0806 */
}

/**
 * check_eapol - EAPOL frame handler
 *
 * @cfg: wifi diag configuration
 * @skb: ieee80211 frame
 *
 * Return: true on match, false otherwise
 */
static bool check_eapol(struct wifi_diag *cfg, struct sk_buff *skb)
{
	return check_etype(skb, ETH_P_PAE); /* 0x888E */
}

struct dns_pkt {
	struct iphdr iph;	/* IP header */
	struct udphdr udph;	/* UDP header */
	__be16 msg_id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned int RD:1;
	unsigned int TC:1;
	unsigned int AA:1;
	unsigned int opcode:4;
	unsigned int QR:1;

	unsigned int rcode:4;
	unsigned int res:3;
	unsigned int RA:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	unsigned int QR:1;
	unsigned int opcode:4;
	unsigned int AA:1;
	unsigned int TC:1;
	unsigned int RD:1;

	unsigned int RA:1;
	unsigned int res:3;
	unsigned int rcode:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
	__be16 QD_count;
	__be16 AN_count;
	__be16 NS_count;
	__be16 AR_count;
	__u8 queries[0];
};

#define DNS_SERVICE_PORT	53

/**
 * check_dns - DNS frame handler
 *
 * @cfg: wifi diag configuration
 * @skb: ieee80211 frame
 *
 * Return: true on match, false otherwise
 */
static bool check_dns(struct wifi_diag *cfg, struct sk_buff *skb)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	int hdr_len;
	int etype;
	struct dns_pkt *b;
	struct iphdr *h;

	if (!ieee80211_is_data(fc))
		return 0;

	hdr_len = ieee80211_hdr_len(skb);

	if (!hdr_len || skb->len < hdr_len + 8)
		return false;

	b = (struct dns_pkt *)&skb->data[hdr_len + 8];
	h = &b->iph;

	if (skb->len < hdr_len + 8 + sizeof(*b))
		return false;

	etype = (skb->data[hdr_len + 6] << 8) + skb->data[hdr_len + 7];

	if (etype != ETH_P_IP ||
	    h->version != 4 ||
	    h->ihl != 5 ||
	    h->protocol != IPPROTO_UDP ||
	    ip_is_fragment(h) ||
	    skb->len < ntohs(h->tot_len) + hdr_len + 8 ||
	    ip_fast_csum((char *)h, h->ihl) ||
	    ntohs(h->tot_len) < ntohs(b->udph.len) + sizeof(struct iphdr))
		return false;

	if (b->udph.source != htons(DNS_SERVICE_PORT) &&
	    b->udph.dest != htons(DNS_SERVICE_PORT))
		return false;

	return true;
}

/**
 * get_dns_info - Get additional DNS frame information
 *
 * @skb: ieee80211 frame
 * @buf: char buffer allocated by caller
 * @size: size of buffer
 *
 * Return: number of characters written to buffer
 */
static int get_dns_info(struct sk_buff *skb, char *buf, size_t size)
{
	int hdr_len;
	struct dns_pkt *b;

	hdr_len = ieee80211_hdr_len(skb);
	b = (struct dns_pkt *)&skb->data[hdr_len + 8];
	return scnprintf(buf, size, "dns %s 0x%04x",
			 b->QR ? "Response" : "Query",
			 be16_to_cpu(b->msg_id));
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
 * check_dhcp - DHCP frame handler
 *
 * @cfg: wifi diag configuration
 * @skb: ieee80211 frame
 *
 * Return: true on match, false otherwise
 */
static bool check_dhcp(struct wifi_diag *cfg, struct sk_buff *skb)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	int hdr_len;
	int etype;
	struct bootp_pkt *b;
	struct iphdr *h;

	if (!ieee80211_is_data(fc))
		return 0;

	hdr_len = ieee80211_hdr_len(skb);

	if (!hdr_len || skb->len < hdr_len + 8)
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
	    ntohs(h->tot_len) < ntohs(b->udph.len) + sizeof(struct iphdr))
		return false;

	if (!(b->udph.source == htons(DHCP_SERVER_PORT) &&
	      b->udph.dest == htons(DHCP_CLIENT_PORT)) &&
	    !(b->udph.source == htons(DHCP_CLIENT_PORT) &&
	      b->udph.dest == htons(DHCP_SERVER_PORT)))
		return false;

	return true;
}

/**
 * check_all_ftypes - check all predefined handlers
 *
 * @cfg: wifi diag configuration
 * @skb: ieee80211 frame
 * @id: if matched, set to index of configured entry
 *
 * Return: true on match, false otherwise
 */
static inline bool check_all_ftypes(struct wifi_diag *cfg,
				    struct sk_buff *skb,
				    u8 *id)
{
	int i;

	spin_lock(&cfg->config_lock);
	for (i = 0; i < MAX_FTYPES; i++) {
		if (cfg->ftypes[i].handler &&
		    cfg->ftypes[i].enable &&
		    cfg->ftypes[i].handler(cfg, skb)) {
			*id = cfg->ftypes[i].id;
			spin_unlock(&cfg->config_lock);
			return true;
		}
	}
	spin_unlock(&cfg->config_lock);

	return false;
}

/**
 * set_mgmt_stype - enable or disable MGMT subtype
 *
 * @cfg: wifi diag configuration
 * @stype: MGMT subtype index, 0~15
 * @allowed: add or remove
 */
static void set_mgmt_stype(struct wifi_diag *cfg, int stype, bool allowed)
{
	stype &= 0x0F;
	if (cfg->allowed_mgmt_stypes & BIT(stype)) {
		if (allowed)
			cfg->enabled_mgmt_stypes |= BIT(stype);
		else
			cfg->enabled_mgmt_stypes &= ~BIT(stype);
	}
}

/**
 * check_mgmt_stype - check all enabled MGMT subtypes
 *
 * @cfg: wifi diag configuration
 * @skb: ieee80211 frame
 * @id: if matched, set to index of configured entry
 *
 * Return: true on match, false otherwise
 */
static inline int check_mgmt_stype(struct wifi_diag *cfg,
				   struct sk_buff *skb,
				   u8 *id)
{
	const struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	bool match = false;

	if (ieee80211_is_mgmt(fc)) {
		u16 stype = (le16_to_cpu(fc) & IEEE80211_FCTL_STYPE) >> 4;
		*id = stype & 0x0F;
		match = BIT(stype & 0x0F) & cfg->enabled_mgmt_stypes;
	}

	return match;
}

/**
 * mac_configured - check if MAC address is configured for diagnostic
 *
 * @cfg: wifi diag configuration
 * @addr: MAC address
 *
 * Return: true on match, false otherwise
 */
static inline bool mac_configured(struct wifi_diag *cfg, u8 *addr)
{
	struct sta_def *p, *n;

	spin_lock(&cfg->station_lock);
	list_for_each_entry_safe(p, n, &cfg->station_list, list) {
		if (ether_addr_equal(p->addr, addr)) {
			spin_unlock(&cfg->station_lock);
			return true;
		}
	}
	spin_unlock(&cfg->station_lock);

	return false;
}

/**
 * get_diag_token - get diagnostic token
 *
 * @cfg: wifi diag configuration
 * @tx: true for TX, false for RX
 *
 * Return: non-zero u16 token
 */
static inline u16 get_diag_token(struct wifi_diag *cfg, bool tx)
{
	u16 token;

	if (tx) {
		cfg->tx_token_counter++;

		if (cfg->tx_token_counter == 0)
			cfg->tx_token_counter++;

		token = cfg->tx_token_counter;
	} else {
		cfg->rx_token_counter++;

		if (cfg->rx_token_counter == 0)
			cfg->rx_token_counter++;

		token = cfg->rx_token_counter;
	}

	return token;
}

/**
 * config_show - show current wifi diagnostic configuration
 *
 * @seq: seq file pointer
 * @v: private
 *
 * Return: always return 0
 */
static int config_show(struct seq_file *seq, void *v)
{
	struct ieee80211_local *local = seq->private;
	struct wifi_diag *cfg = local->wifi_diag_config;
	char *buf;
	const int size = 4096;
	int i, len = 0;
	struct sta_def *p, *n;
	unsigned long flags;

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&cfg->config_mtx);

	seq_printf(seq, "WiFi diagnostic state: %s\n",
		   local->wifi_diag_enable ? "enabled" : "disabled");
	seq_printf(seq, "\nPredefined frame types: [%d/%d]\n",
		   cfg->num_ftypes, MAX_FTYPES);

	spin_lock_irqsave(&cfg->config_lock, flags);
	for (i = 0; i < MAX_FTYPES; i++) {
		if (!cfg->ftypes[i].handler)
			continue;
		len += scnprintf(buf + len, size - len, "\t%s : %s\n",
				 cfg->ftypes[i].name,
				 cfg->ftypes[i].enable ? "en" : "dis");
	}

	len += scnprintf(buf + len, size - len, "\n802.11 MGMT Subtypes:\n");
	for (i = 0; i < MAX_STYPES; i++) {
		if (!(BIT(i) & cfg->enabled_mgmt_stypes))
			continue;
		len += scnprintf(buf + len, size - len,
				 "\t[0x%x] %s\n", i, mtype_str[i]);
	}

	len += scnprintf(buf + len, size - len, "\nEther Types: [%d/%d]\n",
			 cfg->num_etypes, MAX_ETYPES);
	for (i = 0; i < MAX_ETYPES; i++) {
		if (!cfg->etypes[i])
			continue;
		len += scnprintf(buf + len, size - len,
				 "\t0x%04x\n", cfg->etypes[i]);
	}
	spin_unlock_irqrestore(&cfg->config_lock, flags);
	seq_printf(seq, "%s", buf);

	i = 1; len = 0; buf[0] = '\0';
	seq_printf(seq, "\nStation MAC addresses: [%d]\n", cfg->num_stations);
	spin_lock_irqsave(&cfg->station_lock, flags);
	list_for_each_entry_safe(p, n, &cfg->station_list, list) {
		len += scnprintf(buf + len, size - len,
				 "\t[%u] %pM\n", i++, p->addr);
		if (size - len < 100) {
			spin_unlock_irqrestore(&cfg->station_lock, flags);
			seq_printf(seq, "%s", buf);
			len = 0;  buf[0] = '\0';
			spin_lock_irqsave(&cfg->station_lock, flags);
		}
	}
	spin_unlock_irqrestore(&cfg->station_lock, flags);
	seq_printf(seq, "%s", buf);

	mutex_unlock(&cfg->config_mtx);

	kfree(buf);

	return 0;
}

static int ftype_cmd_handler(struct wifi_diag *cfg,
			     int argc, char **argv, bool add)
{
	unsigned long flags;
	int i;

	if (argc < 2)
		return -EINVAL;

	spin_lock_irqsave(&cfg->config_lock, flags);
	for (i = 0; i < MAX_FTYPES; i++) {
		if (cfg->ftypes[i].handler &&
		    !strcmp(argv[1], cfg->ftypes[i].name)) {
			cfg->ftypes[i].enable = add;
			spin_unlock_irqrestore(&cfg->config_lock, flags);

			return CMD_STATUS_HANDLED;
		}
	}
	spin_unlock_irqrestore(&cfg->config_lock, flags);

	return CMD_STATUS_NOOP;
}

static int mgmt_cmd_handler(struct wifi_diag *cfg,
			    int argc, char **argv, bool add)
{
	unsigned long flags;
	unsigned long num;

	if (argc < 3)
		return -EINVAL;

	if (kstrtoul(argv[2], 0, &num))
		return -EINVAL;

	if (num >= MAX_STYPES)
		return -EINVAL;

	spin_lock_irqsave(&cfg->config_lock, flags);
	set_mgmt_stype(cfg, num, add);
	spin_unlock_irqrestore(&cfg->config_lock, flags);

	return CMD_STATUS_HANDLED;
}

static int ether_cmd_handler(struct wifi_diag *cfg,
			     int argc, char **argv, bool add)
{
	unsigned long flags;
	unsigned long num;
	u8 id;
	int i;

	if (argc < 3)
		return -EINVAL;

	if (kstrtoul(argv[2], 0, &num))
		return -EINVAL;

	if (num < ETH_P_802_3_MIN || num > 0xFFFF)
		return -EINVAL;

	spin_lock_irqsave(&cfg->config_lock, flags);

	for (i = 0; i < MAX_ETYPES; i++) {
		if (cfg->etypes[i] && cfg->etypes[i] == num) {
			if (!add) {
				cfg->etypes[i] = 0;
				cfg->num_etypes--;
				remove_match_type(cfg, cfg->etypes_id[i]);
			}
			spin_unlock_irqrestore(&cfg->config_lock, flags);

			return CMD_STATUS_HANDLED;
		}
	}

	if (add) {
		for (i = 0; i < MAX_ETYPES; i++) {
			if (!cfg->etypes[i]) {
				if (add_match_type(cfg, NULL, num, &id)) {
					cfg->etypes[i] = num;
					cfg->etypes_id[i] = id;
					cfg->num_etypes++;
				}
				break;
			}
		}
	}
	spin_unlock_irqrestore(&cfg->config_lock, flags);

	return CMD_STATUS_HANDLED;
}

static int sta_cmd_handler(struct wifi_diag *cfg,
			   int argc, char **argv, bool add)
{
	unsigned long flags;
	u8 mac_addr[ETH_ALEN];
	struct sta_def *p, *n;

	if (argc < 3)
		return -EINVAL;

	if (parse_mac(argv[2], mac_addr) == -1)
		return -EINVAL;

	spin_lock_irqsave(&cfg->station_lock, flags);
	list_for_each_entry_safe(p, n, &cfg->station_list, list) {
		if (ether_addr_equal(p->addr, mac_addr)) {
			if (!add) {
				list_del(&p->list);
				cfg->num_stations--;
			}
			spin_unlock_irqrestore(&cfg->station_lock, flags);
			if (add)
				return CMD_STATUS_HANDLED;
			kfree(p);
			goto log_sta_op;
		}
	}
	spin_unlock_irqrestore(&cfg->station_lock, flags);

	if (add) {
		if (cfg->num_stations == MAX_STATIONS)
			return CMD_STATUS_HANDLED;

		p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;

		ether_addr_copy(p->addr, mac_addr);
		spin_lock_irqsave(&cfg->station_lock, flags);
		list_add_tail(&p->list, &cfg->station_list);
		cfg->num_stations++;
		spin_unlock_irqrestore(&cfg->station_lock, flags);
	}

log_sta_op:
	WD_LOG_INTERNAL("wifi diag: %s MAC %pM\n",
			add ? "add" : "remove",
			mac_addr);

	return CMD_STATUS_HANDLED;
}

static int all_sta_cmd_handler(struct wifi_diag *cfg,
			       int argc, char **argv, bool add)
{
	unsigned long flags;
	struct sta_def *p, *n;

	/* only "rem all-sta" */
	if (argc < 2 || add)
		return -EINVAL;

	spin_lock_irqsave(&cfg->station_lock, flags);
	list_for_each_entry_safe(p, n, &cfg->station_list, list) {
		list_del(&p->list);
		spin_unlock_irqrestore(&cfg->station_lock, flags);
		kfree(p);
		WD_LOG_INTERNAL("wifi diag: remove MAC %pM\n", p->addr);
		spin_lock_irqsave(&cfg->station_lock, flags);
	}
	spin_unlock_irqrestore(&cfg->station_lock, flags);
	cfg->num_stations = 0;

	return CMD_STATUS_HANDLED;
}

/**
 * config_write - parse command and configure wifi diagnostic
 *
 * @file: file pointer
 * @buf: user space buffer
 * @count: size of buffer
 * @ppos: file position
 *
 * Return: count of input consumed, negative values on error
 */
static ssize_t config_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct seq_file *seq = file->private_data;
	struct ieee80211_local *local = seq->private;
	struct wifi_diag *cfg = local->wifi_diag_config;
	char data[DEBUGFS_MAX_INPUT_SZ];
	char *argv[DEBUGFS_MAX_ARGC];
	int argc;
	int ret = -EINVAL;
	bool add = true;

#define CALL_CMDH(cmdh)					\
	do {						\
		ret = cmdh##_cmd_handler(cfg, argc, argv, add);	\
		if (ret != CMD_STATUS_NOOP)		\
			goto cmdh_done;			\
	} while (0)

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (count >= sizeof(data))
		count = sizeof(data) - 1;

	if (copy_from_user(data, buf, count))
		return -EFAULT;

	data[count] = '\0';
	argc = parse_args(data, argv, DEBUGFS_MAX_ARGC);
	if (argc < 2)
		return -EINVAL;

	if (!strcmp(argv[0], "add"))
		add = true;
	else if (!strcmp(argv[0], "rem"))
		add = false;
	else
		return -EINVAL;

	mutex_lock(&cfg->config_mtx);

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

cmdh_done:
	mutex_unlock(&cfg->config_mtx);
	if (ret == CMD_STATUS_HANDLED)
		return count;

	return ret;
}

static int config_open(struct inode *inode, struct file *file)
{
	return single_open(file, config_show, inode->i_private);
}

static const struct file_operations config_ops = {
	.owner   = THIS_MODULE,
	.open    = config_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = config_write,
	.release = single_release,
};

/**
 * wifi_diag_add_debugfs - add wifi diagnostic debugfs entries
 *
 * @local: ieee80211_local pointing to hw
 */
static void wifi_diag_add_debugfs(struct ieee80211_local *local)
{
	struct wifi_diag *cfg = local->wifi_diag_config;
	struct dentry *phyd = local->hw.wiphy->debugfsdir;
	struct dentry *ptd;

	if (!phyd)
		return;

	ptd = debugfs_create_dir("wifi_diag", phyd);
	cfg->debugfsdir = ptd;

	if (!ptd)
		return;

	debugfs_create_bool("enable", S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP,
			    ptd, &local->wifi_diag_enable);
	debugfs_create_file("config", S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP,
			    ptd, local, &config_ops);
}

int wifi_diag_init(struct ieee80211_local *local)
{
	struct wifi_diag *cfg;

	local->wifi_diag_config = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!local->wifi_diag_config)
		return -ENOMEM;

	cfg = local->wifi_diag_config;
	cfg->local = local;

	idr_init(&cfg->match_types);
	mutex_init(&cfg->config_mtx);
	spin_lock_init(&cfg->match_type_lock);
	spin_lock_init(&cfg->config_lock);
	spin_lock_init(&cfg->station_lock);
	INIT_LIST_HEAD(&cfg->station_list);

	/* Install handlers for perdefined frame type checks */
	install_ftype_handler(cfg, "arp", check_arp, NULL, false);
	install_ftype_handler(cfg, "dhcp", check_dhcp, NULL, false);
	install_ftype_handler(cfg, "dns", check_dns, get_dns_info, false);
	install_ftype_handler(cfg, "eapol", check_eapol, NULL, false);

	cfg->allowed_mgmt_stypes = 0x1C0F;
	cfg->enabled_mgmt_stypes = 0;

	wifi_diag_add_debugfs(local);

	WD_LOG_INTERNAL("wifi diag: %s init\n", wiphy_name(local->hw.wiphy));

	return 0;
}
EXPORT_SYMBOL(wifi_diag_init);

void wifi_diag_deinit(struct ieee80211_local *local)
{
	struct wifi_diag *cfg = local->wifi_diag_config;
	unsigned long flags;
	struct sta_def *p, *n;

	if (cfg) {
		debugfs_remove_recursive(cfg->debugfsdir);

		spin_lock_irqsave(&cfg->station_lock, flags);
		list_for_each_entry_safe(p, n, &cfg->station_list, list) {
			list_del(&p->list);
			spin_unlock_irqrestore(&cfg->station_lock, flags);
			kfree(p);
			spin_lock_irqsave(&cfg->station_lock, flags);
		}
		spin_unlock_irqrestore(&cfg->station_lock, flags);

		idr_for_each(&cfg->match_types, free_match_types, NULL);
		idr_destroy(&cfg->match_types);

		kfree(cfg);
		local->wifi_diag_config = NULL;
	}
}
EXPORT_SYMBOL(wifi_diag_deinit);

static inline bool setup_cookie(struct wifi_diag *cfg,
				struct sk_buff *skb,
				bool tx,
				struct wifi_diag_cookie *cookie)
{
	u8 id;

	if (check_mgmt_stype(cfg, skb, &id))
		cookie->flags = F_IS_MGMT;
	else if (check_all_etypes(cfg, skb, &id))
		cookie->flags = F_IS_ETHERTYPE;
	else if (check_all_ftypes(cfg, skb, &id))
		cookie->flags = F_IS_FRAMETYPE;

	if (!cookie->flags)
		return false;

	cookie->id = id;
	cookie->token = get_diag_token(cfg, tx);

	return true;
}

static bool sprintf_cookie(struct ieee80211_local *local,
			   struct wifi_diag_cookie *cookie,
			   char *buf, size_t size)
{
	struct wifi_diag *cfg = local->wifi_diag_config;
	struct match_type *match;
	int len = 0;

	buf[0] = '\0';
	if (cookie->flags & F_IS_MGMT) {
		if (cfg->enabled_mgmt_stypes & BIT(cookie->id & 0x0F))
			len += snprintf(buf, size, "MGMT %s",
					mtype_str[cookie->id & 0x0F]);
		else
			return false;
	} else if (cookie->flags & F_IS_ETHERTYPE) {
		spin_lock_bh(&cfg->match_type_lock);
		match = idr_find(&cfg->match_types, cookie->id);
		if (match)
			len += snprintf(buf, size, "0x%04x", match->etype);
		spin_unlock_bh(&cfg->match_type_lock);
		if (!match)
			return false;
	} else if (cookie->flags & F_IS_FRAMETYPE) {
		spin_lock_bh(&cfg->match_type_lock);
		match = idr_find(&cfg->match_types, cookie->id);
		if (match)
			len += snprintf(buf, size, "%s", match->ftype->name);
		spin_unlock_bh(&cfg->match_type_lock);
		if (!match)
			return false;
	} else {
		return false;
	}

	if (size >= len + 9)
		snprintf(buf + len, size - len, "(%u)", cookie->token);

	return true;
}

static bool sprintf_cookie_ext(struct ieee80211_local *local,
			       struct sk_buff *skb,
			       struct wifi_diag_cookie *cookie,
			       char *buf, size_t size)
{
	struct wifi_diag *cfg = local->wifi_diag_config;
	struct match_type *match;
	int len = 0;

	if (!(cookie->flags & F_IS_FRAMETYPE))
		return sprintf_cookie(local, cookie, buf, size);

	buf[0] = '\0';
	spin_lock_bh(&cfg->match_type_lock);
	match = idr_find(&cfg->match_types, cookie->id);
	if (match) {
		if (match->ftype->get_info)
			len = match->ftype->get_info(skb, buf, size);
		else
			len = snprintf(buf, size, "%s", match->ftype->name);
	}
	spin_unlock_bh(&cfg->match_type_lock);
	if (!match)
		return false;

	if (size >= len + 9)
		snprintf(buf + len, size - len, "(%u)", cookie->token);

	return true;
}

void wifi_diag_set_tx_info(struct ieee80211_local *local,
			   struct sta_info *sta,
			   struct sk_buff *skb)
{
	struct wifi_diag *cfg = local->wifi_diag_config;
	struct ieee80211_hdr *hdr;
	struct ieee80211_tx_info *info;
	struct wifi_diag_cookie *cookie;
	u8 *addr;
	const char *dev_name;
	char cookie_str[LOG_COOKIE_STR_SZ];

	if (!cfg || !skb)
		return;

	hdr = (void *)skb->data;
	info = IEEE80211_SKB_CB(skb);
	info->wifi_diag_cookie = 0;

	if (!IS_ERR_OR_NULL(sta)) {
		addr = sta->addr;
		dev_name = sta->sdata->name;
	} else {
		addr = hdr->addr1;
		dev_name = wiphy_name(local->hw.wiphy);
	}
	if (!mac_configured(cfg, addr))
		return;

	cookie = (struct wifi_diag_cookie *)&info->wifi_diag_cookie;
	setup_cookie(cfg, skb, true, cookie);
	if (sprintf_cookie_ext(local, skb, cookie,
			       cookie_str, LOG_COOKIE_STR_SZ))
		WD_LOG_TXRX("%s: STA %pM TX %s\n",
			    dev_name, addr, cookie_str);
}
EXPORT_SYMBOL(wifi_diag_set_tx_info);

void wifi_diag_set_rx_status(struct ieee80211_local *local,
			     struct sta_info *sta,
			     struct sk_buff *skb)
{
	struct wifi_diag *cfg = local->wifi_diag_config;
	struct ieee80211_hdr *hdr;
	struct ieee80211_rx_status *status;
	struct wifi_diag_cookie *cookie;
	u8 *addr;
	const char *dev_name;
	u16 sn;
	char cookie_str[LOG_COOKIE_STR_SZ];

	if (!cfg || !skb)
		return;

	hdr = (void *)skb->data;
	status = IEEE80211_SKB_RXCB(skb);
	status->wifi_diag_cookie = 0;

	if (!IS_ERR_OR_NULL(sta)) {
		addr = sta->addr;
		dev_name = sta->sdata->name;
	} else {
		addr = hdr->addr2;
		dev_name = wiphy_name(local->hw.wiphy);
	}
	if (!mac_configured(cfg, addr))
		return;

	cookie = (struct wifi_diag_cookie *)&status->wifi_diag_cookie;
	setup_cookie(cfg, skb, false, cookie);
	if (sprintf_cookie_ext(local, skb, cookie,
			       cookie_str, LOG_COOKIE_STR_SZ)) {
		sn = (__le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ) >> 4;
		WD_LOG_TXRX("%s: STA %pM RX %s RSSI=%d SN=%d\n",
			    dev_name, addr, cookie_str,
			    status->signal, sn);
	}
}
EXPORT_SYMBOL(wifi_diag_set_rx_status);

bool wifi_diag_tx_marked(struct sk_buff *skb)
{
	struct ieee80211_tx_info *info;
	struct wifi_diag_cookie *cookie;

	if (!skb)
		return false;

	info = IEEE80211_SKB_CB(skb);
	cookie = (struct wifi_diag_cookie *)&info->wifi_diag_cookie;

	return cookie->flags & F_IS_MARKED;
}
EXPORT_SYMBOL(wifi_diag_tx_marked);

bool wifi_diag_rx_marked(struct sk_buff *skb)
{
	struct ieee80211_rx_status *status;
	struct wifi_diag_cookie *cookie;

	if (!skb)
		return false;

	status = IEEE80211_SKB_RXCB(skb);
	cookie = (struct wifi_diag_cookie *)&status->wifi_diag_cookie;

	return cookie->flags & F_IS_MARKED;
}
EXPORT_SYMBOL(wifi_diag_rx_marked);

void wifi_diag_tx_log_dbg(struct ieee80211_local *local,
			  struct sk_buff *skb,
			  ieee80211_tx_result result,
			  const char *driver,
			  const char *fmt, ...)
{
	struct ieee80211_tx_info *info;
	struct wifi_diag_cookie *cookie;
	struct ieee80211_hdr *hdr;
	char cookie_str[LOG_COOKIE_STR_SZ];
	char prefix[LOG_PREFIX_STR_SZ];
	u8 *ra;
	u16 sn;
	char *result_str;
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	if (!skb)
		return;

	info = IEEE80211_SKB_CB(skb);
	cookie = (struct wifi_diag_cookie *)&info->wifi_diag_cookie;
	if (!(cookie->flags & F_IS_MARKED))
		return;

	if (result == TX_CONTINUE)
		return;
	else if (result == TX_QUEUED)
		result_str = "QUEUED";
	else
		result_str = "DROP";

	if (!sprintf_cookie(local, cookie, cookie_str, LOG_COOKIE_STR_SZ))
		return;

	hdr = (void *)skb->data;
	ra = hdr->addr1;
	sn = (__le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ) >> 4;
	snprintf(prefix, LOG_PREFIX_STR_SZ,
		 "%s: STA %pM TX SN=%u: %s - %s",
		 driver, ra, sn, cookie_str, result_str);

	va_start(args, fmt);
	vaf.va = &args;
	WD_LOG_TXRX("%s %pV\n", prefix, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(wifi_diag_tx_log_dbg);

void wifi_diag_tx_status_log_dbg(struct ieee80211_local *local,
				 struct sk_buff *skb,
				 const char *driver,
				 const char *fmt, ...)
{
	struct ieee80211_tx_info *info;
	struct wifi_diag_cookie *cookie;
	struct ieee80211_hdr *hdr;
	char cookie_str[LOG_COOKIE_STR_SZ];
	char prefix[LOG_PREFIX_STR_SZ];
	bool tx_success;
	/*bool tx_no_ack;*/
	u8 *ra;
	u16 sn;
	char *result_str;
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	if (!skb)
		return;

	info = IEEE80211_SKB_CB(skb);
	cookie = (struct wifi_diag_cookie *)&info->wifi_diag_cookie;
	if (!(cookie->flags & F_IS_MARKED))
		return;

	tx_success = info->flags & IEEE80211_TX_STAT_NOACK_TRANSMITTED ||
		info->flags & IEEE80211_TX_STAT_ACK;

	if (tx_success)
		result_str = "SENT";
	else
		result_str = "FAIL";

	if (!sprintf_cookie(local, cookie, cookie_str, LOG_COOKIE_STR_SZ))
		return;

	hdr = (void *)skb->data;
	ra = hdr->addr1;
	sn = (__le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ) >> 4;
		snprintf(prefix, LOG_PREFIX_STR_SZ,
			 "%s: STA %pM TX SN=%u: %s - %s",
			 driver, ra, sn, cookie_str, result_str);

	va_start(args, fmt);
	vaf.va = &args;
	WD_LOG_TXRX("%s %pV\n", prefix, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(wifi_diag_tx_status_log_dbg);

void wifi_diag_rx_status_log_dbg(struct ieee80211_local *local,
				 struct sk_buff *skb,
				 ieee80211_rx_result result,
				 const char *driver,
				 const char *fmt, ...)
{
	struct ieee80211_rx_status *status;
	struct wifi_diag_cookie *cookie;
	struct ieee80211_hdr *hdr;
	char cookie_str[LOG_COOKIE_STR_SZ];
	char prefix[LOG_PREFIX_STR_SZ];
	u8 *ta;
	u16 sn;
	char *result_str;
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	if (!skb)
		return;

	status = IEEE80211_SKB_RXCB(skb);
	cookie = (struct wifi_diag_cookie *)&status->wifi_diag_cookie;
	if (!(cookie->flags & F_IS_MARKED))
		return;

	if (result == RX_CONTINUE)
		return;
	else if (result == RX_QUEUED)
		result_str = "QUEUED";
	else
		result_str = "DROP";

	if (!sprintf_cookie(local, cookie, cookie_str, LOG_COOKIE_STR_SZ))
		return;

	hdr = (void *)skb->data;
	ta = hdr->addr2;
	sn = (__le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ) >> 4;
	snprintf(prefix, LOG_PREFIX_STR_SZ,
		 "%s: STA %pM RX SN=%u: %s - %s",
		 driver, ta, sn, cookie_str, result_str);

	va_start(args, fmt);
	vaf.va = &args;
	WD_LOG_TXRX("%s %pV\n", prefix, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(wifi_diag_rx_status_log_dbg);
