/*
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "core.h"
#include "wmi-ops.h"
#include "wmi.h"
#include "debug.h"

static char ath10k_map_rate_code_number(u8 rate, u8 pream)
{
	u8 i;
	u8 legacy_rates[] = {TX_CCK_RATE_1_MBPS, TX_CCK_RATE_2_MBPS,
			     TX_CCK_RATE_5_5_MBPS, TX_CCK_RATE_11_MBPS,
			     TX_OFDM_RATE_6_MBPS, TX_OFDM_RATE_9_MBPS,
			     TX_OFDM_RATE_12_MBPS, TX_OFDM_RATE_18_MBPS,
			     TX_OFDM_RATE_24_MBPS, TX_OFDM_RATE_36_MBPS,
			     TX_OFDM_RATE_48_MBPS, TX_OFDM_RATE_54_MBPS};

	/* For CCK 5.5Mbps firmware sends rate as 6 */
	if (pream == WMI_RATE_PREAMBLE_CCK && rate == 6)
		rate = TX_CCK_RATE_5_5_MBPS;

	for (i = 0; i < LEGACY_RATE_NUM; i++) {
		if (rate == legacy_rates[i])
			break;
	}

	return i;
}

void ath10k_update_peer_tx_stats(struct ath10k *ar,
				 struct ath10k_sta *arsta,
				 struct ath10k_per_peer_tx_stats *peer_stats)
{
	u8 pream, bw, mcs, nss, rate, pkts, gi;
	int i, idx;
	struct ath10k_tx_stats *tx_stats;
	bool legacy_rate;

	spin_lock_bh(&ar->data_lock);
	tx_stats = &arsta->tx_stats;
	pkts = peer_stats->tx_ppdu_cnt;

	for (i = 0; i < pkts; i++) {
		pream = ATH10K_HW_PREAMBLE(peer_stats->ratecode[i]);
		legacy_rate = ((pream == WMI_RATE_PREAMBLE_CCK) ||
			       (pream == WMI_RATE_PREAMBLE_OFDM));

		gi = ATH10K_HW_GI(peer_stats->flags[i]);

		if (legacy_rate) {
			rate = ATH10K_HW_LEGACY_RATE(peer_stats->ratecode[i]);
			mcs = ath10k_map_rate_code_number(rate, pream);
			if (mcs == LEGACY_RATE_NUM)
				continue;
			tx_stats->succ_bytes_legacy_rates[mcs] +=
				__le16_to_cpu(peer_stats->success_bytes[i]);
			tx_stats->succ_pkts_legacy_rates[mcs] +=
				(peer_stats->success_pkts[i]);
			tx_stats->fail_bytes_legacy_rates[mcs] +=
				__le16_to_cpu(peer_stats->failed_bytes[i]);
			tx_stats->fail_pkts_legacy_rates[mcs] +=
				(peer_stats->failed_pkts[i]);
			tx_stats->retry_bytes_legacy_rates[mcs] +=
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->retry_pkts_legacy_rates[mcs] +=
				(peer_stats->retry_pkts[i]);
			tx_stats->total_bytes_legacy_rates[mcs] +=
				__le16_to_cpu(peer_stats->success_bytes[i]) +
				__le16_to_cpu(peer_stats->failed_bytes[i]) +
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->total_pkts_legacy_rates[mcs] +=
				(peer_stats->success_pkts[i] +
				peer_stats->failed_pkts[i] +
				peer_stats->retry_pkts[i]);
			tx_stats->ack_fails +=
				ATH10K_HW_BA_FAIL(peer_stats->flags[i]);
		} else {
			bw = ATH10K_HW_BW(peer_stats->flags[i]);
			nss = ATH10K_HW_NSS(peer_stats->ratecode[i]) - 1;
			mcs = ATH10K_HW_MCS_RATE(peer_stats->ratecode[i]);
			idx = mcs * 8 + 8 * 10 * (nss);
			idx += bw * 2 + gi;

			if (nss > 2 || bw > 2 || mcs > 9) {
				continue;
			}
			if (ATH10K_HW_AMPDU(peer_stats->flags[i])) {
				tx_stats->ba_fails +=
					ATH10K_HW_BA_FAIL(peer_stats->flags[i]);
				tx_stats->ampdu_bytes_mcs[mcs] +=
					__le16_to_cpu(peer_stats->success_bytes[i]) +
					__le16_to_cpu(peer_stats->retry_bytes[i]);
				tx_stats->ampdu_bytes_bw[bw] +=
					__le16_to_cpu(peer_stats->success_bytes[i]) +
					__le16_to_cpu(peer_stats->retry_bytes[i]);
				tx_stats->ampdu_bytes_nss[nss] +=
					__le16_to_cpu(peer_stats->success_bytes[i]) +
					__le16_to_cpu(peer_stats->retry_bytes[i]);
				tx_stats->ampdu_bytes_gi[gi] +=
					__le16_to_cpu(peer_stats->success_bytes[i]) +
					__le16_to_cpu(peer_stats->retry_bytes[i]);
				tx_stats->ampdu_bytes_rate_num[idx] +=
					__le16_to_cpu(peer_stats->success_bytes[i]) +
					__le16_to_cpu(peer_stats->retry_bytes[i]);
				tx_stats->ampdu_pkts_mcs[mcs] +=
						(peer_stats->success_pkts[i] +
						 peer_stats->retry_pkts[i]);
				tx_stats->ampdu_pkts_bw[bw] +=
						(peer_stats->success_pkts[i] +
						 peer_stats->retry_pkts[i]);
				tx_stats->ampdu_pkts_nss[nss] +=
						(peer_stats->success_pkts[i] +
						 peer_stats->retry_pkts[i]);
				tx_stats->ampdu_pkts_gi[gi] +=
						(peer_stats->success_pkts[i] +
						 peer_stats->retry_pkts[i]);
				tx_stats->ampdu_pkts_rate_num[idx] +=
						(peer_stats->success_pkts[i] +
						 peer_stats->retry_pkts[i]);
			} else {
				tx_stats->ack_fails +=
					ATH10K_HW_BA_FAIL(peer_stats->flags[i]);
			}
			tx_stats->succ_bytes_mcs[mcs] +=
				__le16_to_cpu(peer_stats->success_bytes[i]);
			tx_stats->succ_bytes_bw[bw] +=
				__le16_to_cpu(peer_stats->success_bytes[i]);
			tx_stats->succ_bytes_nss[nss] +=
				__le16_to_cpu(peer_stats->success_bytes[i]);
			tx_stats->succ_bytes_gi[gi] +=
				__le16_to_cpu(peer_stats->success_bytes[i]);
			tx_stats->succ_bytes_rate_num[idx] +=
				__le16_to_cpu(peer_stats->success_bytes[i]);
			tx_stats->succ_pkts_mcs[mcs] +=
				(peer_stats->success_pkts[i]);
			tx_stats->succ_pkts_bw[bw] +=
				(peer_stats->success_pkts[i]);
			tx_stats->succ_pkts_nss[nss] +=
				(peer_stats->success_pkts[i]);
			tx_stats->succ_pkts_gi[gi] +=
				(peer_stats->success_pkts[i]);
			tx_stats->succ_pkts_rate_num[idx] +=
				(peer_stats->success_pkts[i]);
			tx_stats->fail_bytes_mcs[mcs] +=
				__le16_to_cpu(peer_stats->failed_bytes[i]);
			tx_stats->fail_bytes_bw[bw] +=
				__le16_to_cpu(peer_stats->failed_bytes[i]);
			tx_stats->fail_bytes_nss[nss] +=
				__le16_to_cpu(peer_stats->failed_bytes[i]);
			tx_stats->fail_bytes_gi[gi] +=
				__le16_to_cpu(peer_stats->failed_bytes[i]);
			tx_stats->fail_bytes_rate_num[idx] +=
				__le16_to_cpu(peer_stats->failed_bytes[i]);
			tx_stats->fail_pkts_mcs[mcs] +=
				(peer_stats->failed_pkts[i]);
			tx_stats->fail_pkts_bw[bw] +=
				(peer_stats->failed_pkts[i]);
			tx_stats->fail_pkts_nss[nss] +=
				(peer_stats->failed_pkts[i]);
			tx_stats->fail_pkts_gi[gi] +=
				(peer_stats->failed_pkts[i]);
			tx_stats->fail_pkts_rate_num[idx] +=
				(peer_stats->failed_pkts[i]);
			tx_stats->retry_bytes_mcs[mcs] +=
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->retry_bytes_bw[bw] +=
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->retry_bytes_nss[nss] +=
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->retry_bytes_gi[gi] +=
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->retry_bytes_rate_num[idx] +=
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->retry_pkts_mcs[mcs] +=
				(peer_stats->retry_pkts[i]);
			tx_stats->retry_pkts_bw[bw] +=
				(peer_stats->retry_pkts[i]);
			tx_stats->retry_pkts_nss[nss] +=
				(peer_stats->retry_pkts[i]);
			tx_stats->retry_pkts_gi[gi] +=
				(peer_stats->retry_pkts[i]);
			tx_stats->retry_pkts_rate_num[idx] +=
				(peer_stats->retry_pkts[i]);
			tx_stats->total_bytes_mcs[mcs] +=
				__le16_to_cpu(peer_stats->success_bytes[i]) +
				__le16_to_cpu(peer_stats->failed_bytes[i]) +
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->total_bytes_bw[bw] +=
				__le16_to_cpu(peer_stats->success_bytes[i]) +
				__le16_to_cpu(peer_stats->failed_bytes[i]) +
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->total_bytes_nss[nss] +=
				__le16_to_cpu(peer_stats->success_bytes[i]) +
				__le16_to_cpu(peer_stats->failed_bytes[i]) +
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->total_bytes_gi[gi] +=
				__le16_to_cpu(peer_stats->success_bytes[i]) +
				__le16_to_cpu(peer_stats->failed_bytes[i]) +
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->total_bytes_rate_num[idx] +=
				__le16_to_cpu(peer_stats->success_bytes[i]) +
				__le16_to_cpu(peer_stats->failed_bytes[i]) +
				__le16_to_cpu(peer_stats->retry_bytes[i]);
			tx_stats->total_pkts_mcs[mcs] +=
				peer_stats->success_pkts[i] +
				peer_stats->failed_pkts[i] +
				peer_stats->retry_pkts[i];
			tx_stats->total_pkts_bw[bw] +=
				(peer_stats->success_pkts[i] +
				peer_stats->failed_pkts[i] +
				peer_stats->retry_pkts[i]);
			tx_stats->total_pkts_nss[nss] +=
				(peer_stats->success_pkts[i] +
				peer_stats->failed_pkts[i] +
				peer_stats->retry_pkts[i]);
			tx_stats->total_pkts_gi[gi] +=
				(peer_stats->success_pkts[i] +
				peer_stats->failed_pkts[i] +
				peer_stats->retry_pkts[i]);
			tx_stats->total_pkts_rate_num[idx] +=
				(peer_stats->success_pkts[i] +
				peer_stats->failed_pkts[i] +
				peer_stats->retry_pkts[i]);
		}
	}
	tx_stats->tx_duration += __le32_to_cpu(peer_stats->tx_duration);
	spin_unlock_bh(&ar->data_lock);
}

void ath10k_sta_update_rx_duration(struct ath10k *ar, struct list_head *head)
{	struct ieee80211_sta *sta;
	struct ath10k_fw_stats_peer *peer;
	struct ath10k_sta *arsta;

	rcu_read_lock();
	list_for_each_entry(peer, head, list) {
		sta = ieee80211_find_sta_by_ifaddr(ar->hw, peer->peer_macaddr,
						   NULL);
		if (!sta)
			continue;
		arsta = (struct ath10k_sta *)sta->drv_priv;
		arsta->rx_duration += (u64)peer->rx_duration;
	}
	rcu_read_unlock();
}

static ssize_t ath10k_dbg_sta_read_aggr_mode(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	struct ath10k *ar = arsta->arvif->ar;
	char buf[32];
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "aggregation mode: %s\n",
			(arsta->aggr_mode == ATH10K_DBG_AGGR_MODE_AUTO) ?
			"auto" : "manual");
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath10k_dbg_sta_write_aggr_mode(struct file *file,
					      const char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	struct ath10k *ar = arsta->arvif->ar;
	u32 aggr_mode;
	int ret;

	if (kstrtouint_from_user(user_buf, count, 0, &aggr_mode))
		return -EINVAL;

	if (aggr_mode >= ATH10K_DBG_AGGR_MODE_MAX)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);
	if ((ar->state != ATH10K_STATE_ON) ||
	    (aggr_mode == arsta->aggr_mode)) {
		ret = count;
		goto out;
	}

	ret = ath10k_wmi_addba_clear_resp(ar, arsta->arvif->vdev_id, sta->addr);
	if (ret) {
		ath10k_warn(ar, "failed to clear addba session ret: %d\n", ret);
		goto out;
	}

	arsta->aggr_mode = aggr_mode;
out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_aggr_mode = {
	.read = ath10k_dbg_sta_read_aggr_mode,
	.write = ath10k_dbg_sta_write_aggr_mode,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_dbg_sta_write_addba(struct file *file,
					  const char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	struct ath10k *ar = arsta->arvif->ar;
	u32 tid, buf_size;
	int ret;
	char buf[64];

	simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);

	/* make sure that buf is null terminated */
	buf[sizeof(buf) - 1] = '\0';

	ret = sscanf(buf, "%u %u", &tid, &buf_size);
	if (ret != 2)
		return -EINVAL;

	/* Valid TID values are 0 through 15 */
	if (tid > HTT_DATA_TX_EXT_TID_MGMT - 2)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);
	if ((ar->state != ATH10K_STATE_ON) ||
	    (arsta->aggr_mode != ATH10K_DBG_AGGR_MODE_MANUAL)) {
		ret = count;
		goto out;
	}

	ret = ath10k_wmi_addba_send(ar, arsta->arvif->vdev_id, sta->addr,
				    tid, buf_size);
	if (ret) {
		ath10k_warn(ar, "failed to send addba request: vdev_id %u peer %pM tid %u buf_size %u\n",
			    arsta->arvif->vdev_id, sta->addr, tid, buf_size);
	}

	ret = count;
out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_addba = {
	.write = ath10k_dbg_sta_write_addba,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_dbg_sta_write_addba_resp(struct file *file,
					       const char __user *user_buf,
					       size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	struct ath10k *ar = arsta->arvif->ar;
	u32 tid, status;
	int ret;
	char buf[64];

	simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);

	/* make sure that buf is null terminated */
	buf[sizeof(buf) - 1] = '\0';

	ret = sscanf(buf, "%u %u", &tid, &status);
	if (ret != 2)
		return -EINVAL;

	/* Valid TID values are 0 through 15 */
	if (tid > HTT_DATA_TX_EXT_TID_MGMT - 2)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);
	if ((ar->state != ATH10K_STATE_ON) ||
	    (arsta->aggr_mode != ATH10K_DBG_AGGR_MODE_MANUAL)) {
		ret = count;
		goto out;
	}

	ret = ath10k_wmi_addba_set_resp(ar, arsta->arvif->vdev_id, sta->addr,
					tid, status);
	if (ret) {
		ath10k_warn(ar, "failed to send addba response: vdev_id %u peer %pM tid %u status%u\n",
			    arsta->arvif->vdev_id, sta->addr, tid, status);
	}
	ret = count;
out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_addba_resp = {
	.write = ath10k_dbg_sta_write_addba_resp,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_dbg_sta_write_delba(struct file *file,
					  const char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	struct ath10k *ar = arsta->arvif->ar;
	u32 tid, initiator, reason;
	int ret;
	char buf[64];

	simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);

	/* make sure that buf is null terminated */
	buf[sizeof(buf) - 1] = '\0';

	ret = sscanf(buf, "%u %u %u", &tid, &initiator, &reason);
	if (ret != 3)
		return -EINVAL;

	/* Valid TID values are 0 through 15 */
	if (tid > HTT_DATA_TX_EXT_TID_MGMT - 2)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);
	if ((ar->state != ATH10K_STATE_ON) ||
	    (arsta->aggr_mode != ATH10K_DBG_AGGR_MODE_MANUAL)) {
		ret = count;
		goto out;
	}

	ret = ath10k_wmi_delba_send(ar, arsta->arvif->vdev_id, sta->addr,
				    tid, initiator, reason);
	if (ret) {
		ath10k_warn(ar, "failed to send delba: vdev_id %u peer %pM tid %u initiator %u reason %u\n",
			    arsta->arvif->vdev_id, sta->addr, tid, initiator,
			    reason);
	}
	ret = count;
out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_delba = {
	.write = ath10k_dbg_sta_write_delba,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_dbg_sta_read_rx_duration(struct file *file,
					       char __user *user_buf,
					       size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	char buf[100];
	int len = 0;

	len = scnprintf(buf, sizeof(buf),
			"%llu usecs\n", arsta->rx_duration);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_rx_duration = {
	.read = ath10k_dbg_sta_read_rx_duration,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

#define str(s) #s
#define STATS_OUTPUT_FORMAT(name) 					\
	do {								\
	len += scnprintf(buf + len, size - len, "%s: \n", str(name));	\
	len += scnprintf(buf + len, size - len, "MCS %s: ",		\
		(strstr(str(name), "pkts")) ? "packets" : "bytes");	\
	for (i = 0; i < VHT_MCS_NUM; i++)				\
		len += scnprintf(buf + len, size - len, "%llu, ",	\
				arsta->tx_stats.name## _mcs[i]);	\
	len += scnprintf(buf + len, size - len, "\n");			\
	len += scnprintf(buf + len, size - len,				\
			"BW %s:  20Mhz: %llu\t40Mhz: %llu\t80Mhz: %llu\t",\
		(strstr(str(name), "pkts")) ? "packets" : "bytes",	\
			arsta->tx_stats.name## _bw[0],			\
			arsta->tx_stats.name## _bw[1],			\
			arsta->tx_stats.name## _bw[2]);			\
	len += scnprintf(buf + len, size - len, "160Mhz: %llu\n",	\
			arsta->tx_stats.name## _bw[3]);			\
	len += scnprintf(buf + len, size - len,				\
			"NSS %s: 1x1: %llu\t2x2: %llu\t3x3: %llu\t",	\
		(strstr(str(name), "pkts")) ? "packets" : "bytes",	\
			arsta->tx_stats.name## _nss[0],			\
			arsta->tx_stats.name## _nss[1],			\
			arsta->tx_stats.name## _nss[2]);		\
	len += scnprintf(buf + len, size - len, "4x4: %llu\n",		\
			arsta->tx_stats.name## _nss[3]);		\
	len += scnprintf(buf + len, size - len, "GI %s:  LGI: %llu\t",	\
		(strstr(str(name), "pkts")) ? "packets" : "bytes",	\
			arsta->tx_stats.name## _gi[0]);			\
	len += scnprintf(buf + len, size - len, "SGI: %llu\n",		\
		arsta->tx_stats.name## _gi[1]);			\
	len += scnprintf(buf + len, size - len, "legacy rate %s: ",	\
		(strstr(str(name), "pkts")) ? "packets" : "bytes");	\
	len += scnprintf(buf + len, size - len,				\
			"\t1Mbps: %llu\t2Mbps: %llu\t",			\
			arsta->tx_stats.name## _legacy_rates[0],	\
			arsta->tx_stats.name## _legacy_rates[1]);	\
	len += scnprintf(buf + len, size - len,				\
			"5.5Mbps: %llu\t11Mbps: %llu\n",		\
			arsta->tx_stats.name## _legacy_rates[2],	\
			arsta->tx_stats.name## _legacy_rates[3]);	\
	len += scnprintf(buf + len, size - len,				\
			"\t\t\t6Mbps: %llu\t9Mbps: %llu\t",		\
			arsta->tx_stats.name## _legacy_rates[4],	\
			arsta->tx_stats.name## _legacy_rates[5]);	\
	len += scnprintf(buf + len, size - len,				\
			"12Mbps: %llu\t18Mbps: %llu\n",			\
			arsta->tx_stats.name## _legacy_rates[6],	\
			arsta->tx_stats.name## _legacy_rates[7]);	\
	len += scnprintf(buf + len, size - len,				\
			"\t\t\t24Mbps: %llu\t36Mbps: %llu\t",		\
			arsta->tx_stats.name## _legacy_rates[8],	\
			arsta->tx_stats.name## _legacy_rates[9]);	\
	len += scnprintf(buf + len, size - len,				\
			"48Mbps: %llu\t54Mbps: %llu\n",			\
			arsta->tx_stats.name## _legacy_rates[10],	\
			arsta->tx_stats.name## _legacy_rates[11]);	\
	len += scnprintf(buf + len, size - len, "Rate table %s :\n",	\
		(strstr(str(name), "pkts")) ? "packets" : "bytes");	\
	for (i = 0; i < VHT_RATE_NUM; i++) {				\
		len += scnprintf(buf + len, size - len, "\t%llu",	\
			arsta->tx_stats.name## _rate_num[i]);		\
		if (!((i + 1) % 8))					\
			len += scnprintf(buf + len, size - len, "\n");	\
	}								\
	len += scnprintf(buf + len, size - len, "\n");			\
	} while (0)

static ssize_t ath10k_dbg_sta_dump_tx_stats(struct file *file,
					       char __user *user_buf,
					       size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;
	char *buf;
	int len = 0, i, retval = 0, size = 16*1024;

	buf = kzalloc(size, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	STATS_OUTPUT_FORMAT(succ_pkts);
	STATS_OUTPUT_FORMAT(succ_bytes);
	STATS_OUTPUT_FORMAT(ampdu_pkts);
	STATS_OUTPUT_FORMAT(ampdu_bytes);
	STATS_OUTPUT_FORMAT(fail_pkts);
	STATS_OUTPUT_FORMAT(fail_bytes);
	STATS_OUTPUT_FORMAT(retry_pkts);
	STATS_OUTPUT_FORMAT(retry_bytes);

	len += scnprintf(buf + len, size - len,
			 "\nTX duration:\t %llu usecs\n",
			 arsta->tx_stats.tx_duration);

	len += scnprintf(buf + len, size - len,
			"BA fails:\t %llu\n", arsta->tx_stats.ba_fails);
	len += scnprintf(buf + len, size - len,
			"ACK fails\n %llu\n", arsta->tx_stats.ack_fails);

	if (len > size)
		len = size;
	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	return retval;
}

static const struct file_operations fops_tx_stats = {
	.read = ath10k_dbg_sta_dump_tx_stats,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

void ath10k_sta_add_debugfs(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			    struct ieee80211_sta *sta, struct dentry *dir)
{
	debugfs_create_file("aggr_mode", S_IRUGO | S_IWUSR, dir, sta,
			    &fops_aggr_mode);
	debugfs_create_file("addba", S_IWUSR, dir, sta, &fops_addba);
	debugfs_create_file("addba_resp", S_IWUSR, dir, sta, &fops_addba_resp);
	debugfs_create_file("delba", S_IWUSR, dir, sta, &fops_delba);
	debugfs_create_file("rx_duration", S_IRUGO, dir, sta,
			    &fops_rx_duration);
	debugfs_create_file("tx_stats", S_IRUGO, dir, sta,
			    &fops_tx_stats);
}
