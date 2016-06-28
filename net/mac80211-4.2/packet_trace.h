/*
 * Copyright 2016 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __MAC80211_PACKET_TRACE_H
#define __MAC80211_PACKET_TRACE_H

#include "ieee80211_i.h"

/**
 * DOC: packet trace debugfs interface
 *
 * This is the debugfs interface to configure mac80211 packet trace feature.
 * Two entries will be added for each phyX interface under
 *     /sys/kernel/debug/ieee80211/phyX/packet_trace
 *
 * -rw-rw---- 1 root root 0 Jan  1  1970 ptenable
 * -rw-rw---- 1 root root 0 Jan  1  1970 ptctrl
 *
 * "ptenable" is per-phy global control of packe trace tagging and logging.
 * It's default disabled (N). Write "Y" or "1" to enable, write "N" or "0"
 * to disable.
 *
 * "ptctrl" is the config interface. Write command to this file will configure
 * packet trace accordingly. Read this file will shows the current settings.
 *
 * Commands:
 *   add/rem arp - enable/disable ARP check
 *   add/rem eapol - enable/disable EAPOL check
 *   add/rem dhcp - enable/disable DHCP check
 *
 *   add/rem mgmt # - enable/disable check for MGMT subtype # (0~15)
 *
 *   add/rem ether 0x#### - enable/disable check for ether type 0x####
 *
 *   add/rem sta ##:##:##:##:##:## - enable/disable frame check for station
 *                                   with MAC address ##:##:##:##:##:##
 *
 *   rem all-sta - disable frame check for all stations
 *
 * Example:
 *   echo "add eapol" > ptctrl
 *   echo "rem arp" > ptctrl
 *   echo "add mgmt 0" > ptctrl
 *   echo "add ether 0x0806" > ptctrl
 *   echo "add sta 11:22:33:44:55:66" > ptctrl
 *
 * # cat ptctrl
 * Packet trace debug settings
 *
 * Predefined frame types: [2/8]
 *   arp : disabled
 *   dhcp : enabled
 *   eapol : enabled
 *
 * 802.11 MGMT Subtypes:
 *   ASSOC_REQ
 *
 * Ether Types: [1/8]
 *   0x0806
 *
 * Station MAC addresses: [2/16]
 *  [ 1] 11:22:33:44:55:66
 *  [ 2] aa:bb:cc:dd:ee:ff
 */

#ifdef CONFIG_MAC80211_PACKET_TRACE

/**
 * packet_trace_init - initialize packet trace configuration
 *
 * @local: ieee80211_local pointing to hw
 *
 * Return: 0 on success, other on failure
 */
int packet_trace_init(struct ieee80211_local *local);

/**
 * packet_trace_deinit - de-initialize packet trace configuration
 *
 * @local: ieee80211_local pointing to hw
 */
void packet_trace_deinit(struct ieee80211_local *local);

/**
 * packet_trace_set_tx_info - tag transmit skb for tracing
 *
 * @local: ieee80211_local pointing to hw
 * @sta: ieee80211_sta_info, could be NULL or ERR
 * @skb: skb to be sent
 */
void packet_trace_set_tx_info(struct ieee80211_local *local,
			      struct sta_info *sta,
			      struct sk_buff *skb);

/**
 * packet_trace_set_rx_status - tag received skb for tracing
 *
 * @local: ieee80211_local pointing to hw
 * @sta: ieee80211_sta_info, could be NULL or ERR
 * @skb: skb received
 */
void packet_trace_set_rx_status(struct ieee80211_local *local,
				struct sta_info *sta,
				struct sk_buff *skb);

/**
 * packet_trace_tx_skb_traced - Test if tx skb is being traced
 *
 * @skb: ieee80211 frame
 *
 * Return: true if being traced, false if not
 */
bool packet_trace_tx_skb_traced(struct sk_buff *skb);

/**
 * packet_trace_tx_status_traced - Test if tx status is being traced
 *
 * @skb: ieee80211 frame
 *
 * Return: true if being traced, false if not
 */
#define packet_trace_tx_status_traced(skb)	\
	packet_trace_tx_skb_traced(skb)

/**
 * packet_trace_rx_status_traced - Test if rx status is being traced
 *
 * @skb: ieee80211 frame
 *
 * Return: true if being traced, false if not
 */
bool packet_trace_rx_status_traced(struct sk_buff *skb);

/**
 * packet_trace_tx_log_dbg - log tx result
 *
 * @local: ieee80211_local point to hw
 * @skb: ieee80211 frame
 * @result: ieee80211_tx_resultpacket_trace_set_rx_status
 * @driver: driver name
 */
void packet_trace_tx_log_dbg(struct ieee80211_local *local,
			     struct sk_buff *skb,
			     ieee80211_tx_result result,
			     const char *driver,
			     const char *fmt, ...);

/**
 * packet_trace_tx_status_log_dbg - log tx status
 *
 * @local: ieee80211_local point to hw
 * @skb: ieee80211 frame
 * @driver: driver name
 */
void packet_trace_tx_status_log_dbg(struct ieee80211_local *local,
				    struct sk_buff *skb,
				    const char *driver,
				    const char *fmt, ...);

/**
 * packet_trace_rx_status_log_dbg - log rx status
 *
 * @local: ieee80211_local point to hw
 * @skb: ieee80211 frame
 * @result: ieee80211_rx_result
 * @driver: driver name
 */
void packet_trace_rx_status_log_dbg(struct ieee80211_local *local,
				    struct sk_buff *skb,
				    ieee80211_rx_result result,
				    const char *driver,
				    const char *fmt, ...);

#define PACKET_TRACE_SET_TX_INFO(local, sta, skb)			\
	do {								\
		if (PACKET_TRACE_ENABLED(local))			\
			packet_trace_set_tx_info(local, sta, skb);	\
	} while (0)

#define PACKET_TRACE_SET_RX_STATUS(local, sta, skb)			\
	do {								\
		if (PACKET_TRACE_ENABLED(local))			\
			packet_trace_set_rx_status(local, sta, skb);	\
	} while (0)

#define PACKET_TRACE_TX(skb)			\
	packet_trace_tx_skb_traced(skb)

#define PACKET_TRACE_TX_STATUS(skb)		\
	packet_trace_tx_status_traced(skb)

#define PACKET_TRACE_RX_STATUS(skb)		\
	packet_trace_rx_status_traced(skb)

#define PACKET_TRACE_ENABLED(local)		\
	((local)->pt_enable && (local)->pt_config)

#define LOCAL_DRIVER_STRING(local)		\
	dev_driver_string(wiphy_dev((local)->hw.wiphy))

#define PACKET_TRACE_TX_DBG(tx, result, fmt, ...)			\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED((tx)->local))			\
			break;						\
		name = (tx)->sdata ? (tx)->sdata->name			\
			: LOCAL_DRIVER_STRING((tx)->local);		\
		packet_trace_tx_log_dbg((tx)->local, (tx)->skb, result,	\
					name, fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_TX_SDATA_DBG(sdata, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED((sdata)->local))		\
			break;						\
		name = (sdata)->name;					\
		packet_trace_tx_log_dbg((sdata)->local, skb, result,	\
					name, fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_TX_STA_DBG(sta, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED((sta)->local))		\
			break;						\
		name = (sta)->sdata->name;				\
		packet_trace_tx_log_dbg((sta)->local, skb, result,	\
					name, fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_TX_LOCAL_DBG(local, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED(local))			\
			break;						\
		name = LOCAL_DRIVER_STRING(local);			\
		packet_trace_tx_log_dbg(local, skb, result,		\
					name, fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_TX_STATUS_SDATA_DBG(sdata, skb, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED((sdata)->local))		\
			break;						\
		name = (sdata)->name;					\
		packet_trace_tx_status_log_dbg((sdata)->local, skb,	\
						name,			\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_TX_STATUS_STA_DBG(sta, skb, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED((sta)->local))		\
			break;						\
		name = (sta)->sdata->name;				\
		packet_trace_tx_status_log_dbg((sta)->local, skb,	\
						name,			\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_TX_STATUS_LOCAL_DBG(local, skb, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED(local))			\
			break;						\
		name = LOCAL_DRIVER_STRING(local);			\
		packet_trace_tx_status_log_dbg(local, skb,		\
						name,			\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_RX_DBG(rx, result, fmt, ...)			\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED((rx)->local))			\
			break;						\
		name = (rx)->sdata ? (rx)->sdata->name			\
			: LOCAL_DRIVER_STRING((rx)->local);		\
		packet_trace_rx_status_log_dbg((rx)->local, (rx)->skb,	\
						result, name,		\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_RX_SDATA_DBG(sdata, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED((sdata)->local))		\
			break;						\
		name = (sdata)->name;					\
		packet_trace_rx_status_log_dbg((sdata)->local, skb,	\
						result, name,		\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_RX_STA_DBG(sta, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED((sta)->local))		\
			break;						\
		name = (sta)->sdata->name;				\
		packet_trace_rx_status_log_dbg((sta)->local, skb,	\
						result, name,		\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define PACKET_TRACE_RX_LOCAL_DBG(local, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!PACKET_TRACE_ENABLED(local))			\
			break;						\
		name = LOCAL_DRIVER_STRING(local);			\
		packet_trace_rx_status_log_dbg(local, skb,		\
						result, name,		\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#endif /* CONFIG_MAC80211_PACKET_TRACE */

#endif /* __MAC80211_PACKET_TRACE_H */

