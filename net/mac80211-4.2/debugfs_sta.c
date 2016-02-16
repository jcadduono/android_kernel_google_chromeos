/*
 * Copyright 2003-2005	Devicescape Software, Inc.
 * Copyright (c) 2006	Jiri Benc <jbenc@suse.cz>
 * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2013-2014  Intel Mobile Communications GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/debugfs.h>
#include <linux/ieee80211.h>
#include "ieee80211_i.h"
#include "debugfs.h"
#include "debugfs_sta.h"
#include "sta_info.h"
#include "driver-ops.h"
#include "mesh.h"

/* sta attributtes */

#define STA_READ(name, field, format_string)				\
static ssize_t sta_ ##name## _read(struct file *file,			\
				   char __user *userbuf,		\
				   size_t count, loff_t *ppos)		\
{									\
	struct sta_info *sta = file->private_data;			\
	return mac80211_format_buffer(userbuf, count, ppos, 		\
				      format_string, sta->field);	\
}
#define STA_READ_D(name, field) STA_READ(name, field, "%d\n")

#define STA_OPS(name)							\
static const struct file_operations sta_ ##name## _ops = {		\
	.read = sta_##name##_read,					\
	.open = simple_open,						\
	.llseek = generic_file_llseek,					\
}

#define STA_OPS_RW(name)						\
static const struct file_operations sta_ ##name## _ops = {		\
	.read = sta_##name##_read,					\
	.write = sta_##name##_write,					\
	.open = simple_open,						\
	.llseek = generic_file_llseek,					\
}

#define STA_FILE(name, field, format)					\
		STA_READ_##format(name, field)				\
		STA_OPS(name)

STA_FILE(aid, sta.aid, D);
STA_FILE(last_ack_signal, last_ack_signal, D);

static ssize_t sta_flags_read(struct file *file, char __user *userbuf,
			      size_t count, loff_t *ppos)
{
	char buf[121];
	struct sta_info *sta = file->private_data;

#define TEST(flg) \
	test_sta_flag(sta, WLAN_STA_##flg) ? #flg "\n" : ""

	int res = scnprintf(buf, sizeof(buf),
			    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
			    TEST(AUTH), TEST(ASSOC), TEST(PS_STA),
			    TEST(PS_DRIVER), TEST(AUTHORIZED),
			    TEST(SHORT_PREAMBLE),
			    sta->sta.wme ? "WME\n" : "",
			    TEST(WDS), TEST(CLEAR_PS_FILT),
			    TEST(MFP), TEST(BLOCK_BA), TEST(PSPOLL),
			    TEST(UAPSD), TEST(SP), TEST(TDLS_PEER),
			    TEST(TDLS_PEER_AUTH), TEST(TDLS_INITIATOR),
			    TEST(TDLS_CHAN_SWITCH), TEST(TDLS_OFF_CHANNEL),
			    TEST(4ADDR_EVENT), TEST(INSERTED),
			    TEST(RATE_CONTROL), TEST(TOFFSET_KNOWN),
			    TEST(MPSP_OWNER), TEST(MPSP_RECIPIENT));
#undef TEST
	return simple_read_from_buffer(userbuf, count, ppos, buf, res);
}
STA_OPS(flags);

static ssize_t sta_num_ps_buf_frames_read(struct file *file,
					  char __user *userbuf,
					  size_t count, loff_t *ppos)
{
	struct sta_info *sta = file->private_data;
	char buf[17*IEEE80211_NUM_ACS], *p = buf;
	int ac;

	for (ac = 0; ac < IEEE80211_NUM_ACS; ac++)
		p += scnprintf(p, sizeof(buf)+buf-p, "AC%d: %d\n", ac,
			       skb_queue_len(&sta->ps_tx_buf[ac]) +
			       skb_queue_len(&sta->tx_filtered[ac]));
	return simple_read_from_buffer(userbuf, count, ppos, buf, p - buf);
}
STA_OPS(num_ps_buf_frames);

static ssize_t sta_last_seq_ctrl_read(struct file *file, char __user *userbuf,
				      size_t count, loff_t *ppos)
{
	char buf[15*IEEE80211_NUM_TIDS], *p = buf;
	int i;
	struct sta_info *sta = file->private_data;
	for (i = 0; i < IEEE80211_NUM_TIDS; i++)
		p += scnprintf(p, sizeof(buf)+buf-p, "%x ",
			       le16_to_cpu(sta->last_seq_ctrl[i]));
	p += scnprintf(p, sizeof(buf)+buf-p, "\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, p - buf);
}
STA_OPS(last_seq_ctrl);

static ssize_t sta_agg_status_read(struct file *file, char __user *userbuf,
					size_t count, loff_t *ppos)
{
	char buf[71 + IEEE80211_NUM_TIDS * 40], *p = buf;
	int i;
	struct sta_info *sta = file->private_data;
	struct tid_ampdu_rx *tid_rx;
	struct tid_ampdu_tx *tid_tx;

	rcu_read_lock();

	p += scnprintf(p, sizeof(buf) + buf - p, "next dialog_token: %#02x\n",
			sta->ampdu_mlme.dialog_token_allocator + 1);
	p += scnprintf(p, sizeof(buf) + buf - p,
		       "TID\t\tRX\tDTKN\tSSN\t\tTX\tDTKN\tpending\n");

	for (i = 0; i < IEEE80211_NUM_TIDS; i++) {
		tid_rx = rcu_dereference(sta->ampdu_mlme.tid_rx[i]);
		tid_tx = rcu_dereference(sta->ampdu_mlme.tid_tx[i]);

		p += scnprintf(p, sizeof(buf) + buf - p, "%02d", i);
		p += scnprintf(p, sizeof(buf) + buf - p, "\t\t%x", !!tid_rx);
		p += scnprintf(p, sizeof(buf) + buf - p, "\t%#.2x",
				tid_rx ? tid_rx->dialog_token : 0);
		p += scnprintf(p, sizeof(buf) + buf - p, "\t%#.3x",
				tid_rx ? tid_rx->ssn : 0);

		p += scnprintf(p, sizeof(buf) + buf - p, "\t\t%x", !!tid_tx);
		p += scnprintf(p, sizeof(buf) + buf - p, "\t%#.2x",
				tid_tx ? tid_tx->dialog_token : 0);
		p += scnprintf(p, sizeof(buf) + buf - p, "\t%03d",
				tid_tx ? skb_queue_len(&tid_tx->pending) : 0);
		p += scnprintf(p, sizeof(buf) + buf - p, "\n");
	}
	rcu_read_unlock();

	return simple_read_from_buffer(userbuf, count, ppos, buf, p - buf);
}

static ssize_t sta_agg_status_write(struct file *file, const char __user *userbuf,
				    size_t count, loff_t *ppos)
{
	char _buf[12] = {}, *buf = _buf;
	struct sta_info *sta = file->private_data;
	bool start, tx;
	unsigned long tid;
	int ret;

	if (count > sizeof(_buf))
		return -EINVAL;

	if (copy_from_user(buf, userbuf, count))
		return -EFAULT;

	buf[sizeof(_buf) - 1] = '\0';

	if (strncmp(buf, "tx ", 3) == 0) {
		buf += 3;
		tx = true;
	} else if (strncmp(buf, "rx ", 3) == 0) {
		buf += 3;
		tx = false;
	} else
		return -EINVAL;

	if (strncmp(buf, "start ", 6) == 0) {
		buf += 6;
		start = true;
		if (!tx)
			return -EINVAL;
	} else if (strncmp(buf, "stop ", 5) == 0) {
		buf += 5;
		start = false;
	} else
		return -EINVAL;

	ret = kstrtoul(buf, 0, &tid);
	if (ret)
		return ret;

	if (tid >= IEEE80211_NUM_TIDS)
		return -EINVAL;

	if (tx) {
		if (start)
			ret = ieee80211_start_tx_ba_session(&sta->sta, tid, 5000);
		else
			ret = ieee80211_stop_tx_ba_session(&sta->sta, tid);
	} else {
		__ieee80211_stop_rx_ba_session(sta, tid, WLAN_BACK_RECIPIENT,
					       3, true);
		ret = 0;
	}

	return ret ?: count;
}
STA_OPS_RW(agg_status);

static ssize_t sta_ht_capa_read(struct file *file, char __user *userbuf,
				size_t count, loff_t *ppos)
{
#define PRINT_HT_CAP(_cond, _str) \
	do { \
	if (_cond) \
			p += scnprintf(p, sizeof(buf)+buf-p, "\t" _str "\n"); \
	} while (0)
	char buf[512], *p = buf;
	int i;
	struct sta_info *sta = file->private_data;
	struct ieee80211_sta_ht_cap *htc = &sta->sta.ht_cap;

	p += scnprintf(p, sizeof(buf) + buf - p, "ht %ssupported\n",
			htc->ht_supported ? "" : "not ");
	if (htc->ht_supported) {
		p += scnprintf(p, sizeof(buf)+buf-p, "cap: %#.4x\n", htc->cap);

		PRINT_HT_CAP((htc->cap & BIT(0)), "RX LDPC");
		PRINT_HT_CAP((htc->cap & BIT(1)), "HT20/HT40");
		PRINT_HT_CAP(!(htc->cap & BIT(1)), "HT20");

		PRINT_HT_CAP(((htc->cap >> 2) & 0x3) == 0, "Static SM Power Save");
		PRINT_HT_CAP(((htc->cap >> 2) & 0x3) == 1, "Dynamic SM Power Save");
		PRINT_HT_CAP(((htc->cap >> 2) & 0x3) == 3, "SM Power Save disabled");

		PRINT_HT_CAP((htc->cap & BIT(4)), "RX Greenfield");
		PRINT_HT_CAP((htc->cap & BIT(5)), "RX HT20 SGI");
		PRINT_HT_CAP((htc->cap & BIT(6)), "RX HT40 SGI");
		PRINT_HT_CAP((htc->cap & BIT(7)), "TX STBC");

		PRINT_HT_CAP(((htc->cap >> 8) & 0x3) == 0, "No RX STBC");
		PRINT_HT_CAP(((htc->cap >> 8) & 0x3) == 1, "RX STBC 1-stream");
		PRINT_HT_CAP(((htc->cap >> 8) & 0x3) == 2, "RX STBC 2-streams");
		PRINT_HT_CAP(((htc->cap >> 8) & 0x3) == 3, "RX STBC 3-streams");

		PRINT_HT_CAP((htc->cap & BIT(10)), "HT Delayed Block Ack");

		PRINT_HT_CAP(!(htc->cap & BIT(11)), "Max AMSDU length: "
			     "3839 bytes");
		PRINT_HT_CAP((htc->cap & BIT(11)), "Max AMSDU length: "
			     "7935 bytes");

		/*
		 * For beacons and probe response this would mean the BSS
		 * does or does not allow the usage of DSSS/CCK HT40.
		 * Otherwise it means the STA does or does not use
		 * DSSS/CCK HT40.
		 */
		PRINT_HT_CAP((htc->cap & BIT(12)), "DSSS/CCK HT40");
		PRINT_HT_CAP(!(htc->cap & BIT(12)), "No DSSS/CCK HT40");

		/* BIT(13) is reserved */

		PRINT_HT_CAP((htc->cap & BIT(14)), "40 MHz Intolerant");

		PRINT_HT_CAP((htc->cap & BIT(15)), "L-SIG TXOP protection");

		p += scnprintf(p, sizeof(buf)+buf-p, "ampdu factor/density: %d/%d\n",
				htc->ampdu_factor, htc->ampdu_density);
		p += scnprintf(p, sizeof(buf)+buf-p, "MCS mask:");

		for (i = 0; i < IEEE80211_HT_MCS_MASK_LEN; i++)
			p += scnprintf(p, sizeof(buf)+buf-p, " %.2x",
					htc->mcs.rx_mask[i]);
		p += scnprintf(p, sizeof(buf)+buf-p, "\n");

		/* If not set this is meaningless */
		if (le16_to_cpu(htc->mcs.rx_highest)) {
			p += scnprintf(p, sizeof(buf)+buf-p,
				       "MCS rx highest: %d Mbps\n",
				       le16_to_cpu(htc->mcs.rx_highest));
		}

		p += scnprintf(p, sizeof(buf)+buf-p, "MCS tx params: %x\n",
				htc->mcs.tx_params);
	}

	return simple_read_from_buffer(userbuf, count, ppos, buf, p - buf);
}
STA_OPS(ht_capa);

static ssize_t sta_rx_stats_read(struct file *file, char __user *userbuf,
				 size_t count, loff_t *ppos)
{
	int retval = 0, len = 0;
	char *buf;
	const int size = 2816;  /* adjust the size for all items */
	struct sta_info *sta = file->private_data;
	struct ieee80211_local *local = sta->local;
	int i;

	if (!local->rx_stats_enabled)
		return -ENOTSUPP;

	buf = kzalloc(size, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	len += scnprintf(buf + len, size - len, "MCS packets: ");
	for (i = 0; i < IEEE80211_VHT_MCS_NUM; i++)
		len += scnprintf(buf + len, size - len, "%llu, ",
				 sta->rx_mcs_pkt[i]);
	len += scnprintf(buf + len, size - len, "\n");
	len += scnprintf(buf + len, size - len,
			"BW packets:  20Mhz: %llu\t40Mhz: %llu\t80Mhz: %llu\t",
			sta->rx_bw_pkt[0], sta->rx_bw_pkt[1],
			sta->rx_bw_pkt[2]);
	len += scnprintf(buf + len, size - len, "160Mhz: %llu\n",
			sta->rx_bw_pkt[3]);

	len += scnprintf(buf + len, size - len,
			"NSS packets: 1x1: %llu\t2x2: %llu\t3x3: %llu\t",
			sta->rx_nss_pkt[0], sta->rx_nss_pkt[1],
			sta->rx_nss_pkt[2]);
	len += scnprintf(buf + len, size - len, "4x4: %llu\n",
			sta->rx_nss_pkt[3]);

	len += scnprintf(buf + len, size - len, "GI packets:  LGI: %llu\t",
			sta->rx_gi_pkt[0]);
	len += scnprintf(buf + len, size - len, "SGI: %llu\n",
			sta->rx_gi_pkt[1]);
	len += scnprintf(buf + len, size - len, "legacy rate packets: ");
	len += scnprintf(buf + len, size - len,
			"\t1Mbps: %llu\t2Mbps: %llu\t",
			sta->rx_legacy_pkt[0], sta->rx_legacy_pkt[1]);
	len += scnprintf(buf + len, size - len,
			"5.5Mbps: %llu\t11Mbps: %llu\n",
			sta->rx_legacy_pkt[2], sta->rx_legacy_pkt[3]);
	len += scnprintf(buf + len, size - len,
			"\t\t\t6Mbps: %llu\t9Mbps: %llu\t",
			sta->rx_legacy_pkt[4], sta->rx_legacy_pkt[5]);
	len += scnprintf(buf + len, size - len,
			"12Mbps: %llu\t18Mbps: %llu\n",
			sta->rx_legacy_pkt[6], sta->rx_legacy_pkt[7]);
	len += scnprintf(buf + len, size - len,
			"\t\t\t24Mbps: %llu\t36Mbps: %llu\t",
			sta->rx_legacy_pkt[8], sta->rx_legacy_pkt[9]);
	len += scnprintf(buf + len, size - len,
			"48Mbps: %llu\t54Mbps: %llu\n",
			sta->rx_legacy_pkt[10], sta->rx_legacy_pkt[11]);

	len += scnprintf(buf + len, size - len, "Rate table packets:  ");
	for (i = 0; i < IEEE80211_VHT_RATE_NUM; i++) {
		len += scnprintf(buf + len, size - len, "\t%llu",
				 sta->rx_rate_pkt[i]);
		if (!((i + 1) % 8))
			len += scnprintf(buf + len, size - len, "\n\t\t    ");
	}
	len += scnprintf(buf + len, size - len, "\n\n");

	/* Below function can be merged into a macro with above part*/
	len += scnprintf(buf + len, size - len, "MCS bytes: ");
	for (i = 0; i < IEEE80211_VHT_MCS_NUM; i++)
		len += scnprintf(buf + len, size - len, "%llu, ",
				 sta->rx_mcs_byte[i]);
	len += scnprintf(buf + len, size - len, "\n");
	len += scnprintf(buf + len, size - len,
			 "BW bytes:  20Mhz: %llu, 40Mhz: %llu, 80Mhz: %llu, 160Mhz: %llu\n",
			 sta->rx_bw_byte[0], sta->rx_bw_byte[1],
			 sta->rx_bw_byte[2], sta->rx_bw_byte[3]);
	len += scnprintf(buf + len, size - len,
			 "NSS bytes: 1x1: %llu, 2x2: %llu, 3x3: %llu, 4x4: %llu\n",
			 sta->rx_nss_byte[0], sta->rx_nss_byte[1],
			 sta->rx_nss_byte[2], sta->rx_nss_byte[3]);
	len += scnprintf(buf + len, size - len,
			 "GI bytes:  LGI: %llu, SGI: %llu\n",
			 sta->rx_gi_byte[0], sta->rx_gi_byte[1]);
	len += scnprintf(buf + len, size - len, "legacy rate bytes: ");
	len += scnprintf(buf + len, size - len,
			 "\t1Mbps: %llu\t2Mbps: %llu\t5.5Mbps: %llu\t11Mbps: %llu\n"
			 "\t\t\t6Mbps: %llu\t9Mbps: %llu\t12Mbps: %llu\t18Mbps: %llu\n"
			 "\t\t\t24Mbps: %llu\t36Mbps: %llu\t48Mbps: %llu\t54Mbps: %llu\n",
			 sta->rx_legacy_byte[0], sta->rx_legacy_byte[1],
			 sta->rx_legacy_byte[2], sta->rx_legacy_byte[3],
			 sta->rx_legacy_byte[4], sta->rx_legacy_byte[5],
			 sta->rx_legacy_byte[6], sta->rx_legacy_byte[7],
			 sta->rx_legacy_byte[8], sta->rx_legacy_byte[9],
			 sta->rx_legacy_byte[10], sta->rx_legacy_byte[11]);

	len += scnprintf(buf + len, size - len, "Rate table bytes:  ");
	for (i = 0; i < IEEE80211_VHT_RATE_NUM; i++) {
		len += scnprintf(buf + len, size - len, "\t%llu",
				 sta->rx_rate_byte[i]);
		if (!((i + 1) % 8))
			len += scnprintf(buf + len, size - len, "\n\t\t    ");
	}
	len += scnprintf(buf + len, size - len, "\n");

	if (len > size)
		len = size;
	retval = simple_read_from_buffer(userbuf, count, ppos, buf, len);

	kfree(buf);

	return retval;
}
STA_OPS(rx_stats);

static ssize_t sta_vht_capa_read(struct file *file, char __user *userbuf,
				 size_t count, loff_t *ppos)
{
	char buf[128], *p = buf;
	struct sta_info *sta = file->private_data;
	struct ieee80211_sta_vht_cap *vhtc = &sta->sta.vht_cap;

	p += scnprintf(p, sizeof(buf) + buf - p, "VHT %ssupported\n",
			vhtc->vht_supported ? "" : "not ");
	if (vhtc->vht_supported) {
		p += scnprintf(p, sizeof(buf)+buf-p, "cap: %#.8x\n", vhtc->cap);

		p += scnprintf(p, sizeof(buf)+buf-p, "RX MCS: %.4x\n",
			       le16_to_cpu(vhtc->vht_mcs.rx_mcs_map));
		if (vhtc->vht_mcs.rx_highest)
			p += scnprintf(p, sizeof(buf)+buf-p,
				       "MCS RX highest: %d Mbps\n",
				       le16_to_cpu(vhtc->vht_mcs.rx_highest));
		p += scnprintf(p, sizeof(buf)+buf-p, "TX MCS: %.4x\n",
			       le16_to_cpu(vhtc->vht_mcs.tx_mcs_map));
		if (vhtc->vht_mcs.tx_highest)
			p += scnprintf(p, sizeof(buf)+buf-p,
				       "MCS TX highest: %d Mbps\n",
				       le16_to_cpu(vhtc->vht_mcs.tx_highest));
	}

	return simple_read_from_buffer(userbuf, count, ppos, buf, p - buf);
}
STA_OPS(vht_capa);

#ifdef CONFIG_MAC80211_MESH
static ssize_t sta_mesh_link_metric_read(struct file *file,
	char __user *userbuf, size_t count, loff_t *ppos)
{
	char buf[12], *p = buf;
	struct sta_info *sta = file->private_data;
	struct ieee80211_local *local = sta->local;
	u32 metric;

	rcu_read_lock();
	metric = airtime_link_metric_get(local, sta);
	rcu_read_unlock();

	p += scnprintf(p, sizeof(buf)+buf-p, "%d\n", metric);

	return simple_read_from_buffer(userbuf, count, ppos, buf, p - buf);
}

STA_OPS(mesh_link_metric);

#endif

#define DEBUGFS_ADD(name) \
	debugfs_create_file(#name, 0400, \
		sta->debugfs.dir, sta, &sta_ ##name## _ops);

#define DEBUGFS_ADD_COUNTER(name, field)				\
	if (sizeof(sta->field) == sizeof(u32))				\
		debugfs_create_u32(#name, 0400, sta->debugfs.dir,	\
			(u32 *) &sta->field);				\
	else								\
		debugfs_create_u64(#name, 0400, sta->debugfs.dir,	\
			(u64 *) &sta->field);

void ieee80211_rx_h_sta_stats(struct sta_info *sta, struct sk_buff *skb)
{
	struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct ieee80211_local *local = sta->local;
	unsigned int pkt_len = skb->len;
	unsigned int bw_idx, gi_idx, i;

	if (!local->rx_stats_enabled)
		return;

	if (is_multicast_ether_addr(hdr->addr1) ||
	    !ieee80211_is_data(hdr->frame_control))
		goto out;

	/* Not support 5Mhz and 10Mhz currently  */
	if (status->flag & (RX_FLAG_5MHZ | RX_FLAG_10MHZ))
		goto out;

	if (status->vht_flag & RX_VHT_FLAG_160MHZ)
		bw_idx = 3;
	else if (status->vht_flag & RX_VHT_FLAG_80MHZ)
		bw_idx = 2;
	else if (status->flag & RX_FLAG_40MHZ)
		bw_idx = 1;
	else
		bw_idx = 0;

	sta->rx_bw_pkt[bw_idx]++;
	sta->rx_bw_byte[bw_idx] += pkt_len;


	gi_idx = (status->flag & RX_FLAG_SHORT_GI) ? 1 : 0;
	sta->rx_gi_pkt[gi_idx]++;
	sta->rx_gi_byte[gi_idx] += pkt_len;

	if (status->flag & RX_FLAG_VHT) {
		/* Keep silent quit for all packet not statisfy the
		 * statistics requirement in the data path
		 */
		if (status->rate_idx > (IEEE80211_VHT_MCS_NUM - 1))
			goto out;

		if (status->vht_nss > IEEE80211_VHT_NSS_NUM ||
		    !status->vht_nss)
			goto out;

		sta->rx_nss_pkt[status->vht_nss - 1]++;
		sta->rx_nss_byte[status->vht_nss - 1] += pkt_len;

		sta->rx_mcs_pkt[status->rate_idx]++;
		sta->rx_mcs_byte[status->rate_idx] += pkt_len;

		i = status->rate_idx * 8 + 8 * 10 * (status->vht_nss - 1);
		i += bw_idx * 2 + gi_idx;
		sta->rx_rate_pkt[i]++;
		sta->rx_rate_byte[i] += pkt_len;
	} else {
		struct ieee80211_supported_band *sband;
		int shift = ieee80211_vif_get_shift(&sta->sdata->vif);
		u16 brate, legacy_rate;

		if (status->rate_idx > (IEEE80211_RX_LEGACY_RATE_NUM - 1))
			goto out;

		sband = sta->local->hw.wiphy->bands[
			ieee80211_get_sdata_band(sta->sdata)];
		brate = sband->bitrates[status->rate_idx].bitrate;
		legacy_rate = DIV_ROUND_UP(brate, 1 << shift);

		switch (legacy_rate) {
		case 10:
			i = 0;
			break;
		case 20:
			i = 1;
			break;
		case 55:
			i = 2;
			break;
		case 110:
			i = 3;
			break;
		case 60:
			i = 4;
			break;
		case 90:
			i = 5;
			break;
		case 120:
			i = 6;
			break;
		case 180:
			i = 7;
			break;
		case 240:
			i = 8;
			break;
		case 360:
			i = 9;
			break;
		case 480:
			i = 10;
			break;
		case 540:
			i = 11;
			break;
		default:
			goto out;
		}
		sta->rx_legacy_pkt[i]++;
		sta->rx_legacy_byte[i] += pkt_len;
	}
out:
	return;
}

void ieee80211_sta_debugfs_add(struct sta_info *sta)
{
	struct ieee80211_local *local = sta->local;
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct dentry *stations_dir = sta->sdata->debugfs.subdir_stations;
	u8 mac[3*ETH_ALEN];

	sta->debugfs.add_has_run = true;

	if (!stations_dir)
		return;

	snprintf(mac, sizeof(mac), "%pM", sta->sta.addr);

	/*
	 * This might fail due to a race condition:
	 * When mac80211 unlinks a station, the debugfs entries
	 * remain, but it is already possible to link a new
	 * station with the same address which triggers adding
	 * it to debugfs; therefore, if the old station isn't
	 * destroyed quickly enough the old station's debugfs
	 * dir might still be around.
	 */
	sta->debugfs.dir = debugfs_create_dir(mac, stations_dir);
	if (!sta->debugfs.dir)
		return;

	DEBUGFS_ADD(flags);
	DEBUGFS_ADD(num_ps_buf_frames);
	DEBUGFS_ADD(last_seq_ctrl);
	DEBUGFS_ADD(agg_status);
	DEBUGFS_ADD(ht_capa);
	DEBUGFS_ADD(vht_capa);
	DEBUGFS_ADD(rx_stats);
	DEBUGFS_ADD(last_ack_signal);

	DEBUGFS_ADD_COUNTER(rx_duplicates, num_duplicates);
	DEBUGFS_ADD_COUNTER(rx_fragments, rx_fragments);
	DEBUGFS_ADD_COUNTER(tx_filtered, tx_filtered_count);

#ifdef CONFIG_MAC80211_MESH
	DEBUGFS_ADD(mesh_link_metric);
#endif

	if (sizeof(sta->driver_buffered_tids) == sizeof(u32))
		debugfs_create_x32("driver_buffered_tids", 0400,
				   sta->debugfs.dir,
				   (u32 *)&sta->driver_buffered_tids);
	else
		debugfs_create_x64("driver_buffered_tids", 0400,
				   sta->debugfs.dir,
				   (u64 *)&sta->driver_buffered_tids);

	drv_sta_add_debugfs(local, sdata, &sta->sta, sta->debugfs.dir);
}

void ieee80211_sta_debugfs_remove(struct sta_info *sta)
{
	struct ieee80211_local *local = sta->local;
	struct ieee80211_sub_if_data *sdata = sta->sdata;

	drv_sta_remove_debugfs(local, sdata, &sta->sta, sta->debugfs.dir);
	debugfs_remove_recursive(sta->debugfs.dir);
	sta->debugfs.dir = NULL;
}
