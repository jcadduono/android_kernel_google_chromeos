/*
 * Copyright 2016 Google, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __MAC80211_WIFI_DIAG_H
#define __MAC80211_WIFI_DIAG_H

#include "ieee80211_i.h"

/**
 * DOC: WiFi diagnostic debugfs interface
 *
 * This is the debugfs interface to configure mac80211 WiFi diagnostic feature.
 * Two entries will be added for each phyX interface under
 *     /sys/kernel/debug/ieee80211/phyX/wifi_diag
 *
 * -rw-rw---- 1 root root 0 Jan  1  1970 enable
 * -rw-rw---- 1 root root 0 Jan  1  1970 config
 *
 * "enable" is per-phy global control of WiFi diag tagging and logging. It's
 * default disabled (N). Write "Y" or "1" to enable, write "N" or "0" to
 * disable.
 *
 * "config" is the config interface. Write command to this file will configure
 * WiFi diag accordingly. Read this file will shows the current settings.
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
 *   echo "add eapol" > config
 *   echo "rem arp" > config
 *   echo "add mgmt 0" > config
 *   echo "add ether 0x0806" > config
 *   echo "add sta 11:22:33:44:55:66" > config
 *
 * # cat config
 * WiFi diagnostic state: enabled
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

#ifdef CONFIG_MAC80211_WIFI_DIAG

/**
 * wifi_diag_init - initialize WiFi diagnostic configuration
 *
 * @local: ieee80211_local pointing to hw
 *
 * Return: 0 on success, other on failure
 */
int wifi_diag_init(struct ieee80211_local *local);

/**
 * wifi_diag_deinit - de-initialize WiFi diagnostic configuration
 *
 * @local: ieee80211_local pointing to hw
 */
void wifi_diag_deinit(struct ieee80211_local *local);

/**
 * wifi_diag_set_tx_info - tag transmit skb for tracing
 *
 * @local: ieee80211_local pointing to hw
 * @sta: ieee80211_sta_info, could be NULL or ERR
 * @skb: skb to be sent
 */
void wifi_diag_set_tx_info(struct ieee80211_local *local,
			   struct sta_info *sta,
			   struct sk_buff *skb);

/**
 * wifi_diag_set_rx_status - tag received skb for tracing
 *
 * @local: ieee80211_local pointing to hw
 * @sta: ieee80211_sta_info, could be NULL or ERR
 * @skb: skb received
 */
void wifi_diag_set_rx_status(struct ieee80211_local *local,
			     struct sta_info *sta,
			     struct sk_buff *skb);

/**
 * wifi_diag_tx_marked - Test if tx skb is marked for diagnostic
 *
 * @skb: ieee80211 frame
 *
 * Return: true if marked, false if not
 */
bool wifi_diag_tx_marked(struct sk_buff *skb);

/**
 * wifi_diag_rx_marked - Test if rx status is mark for diagnostic
 *
 * @skb: ieee80211 frame
 *
 * Return: true if marked, false if not
 */
bool wifi_diag_rx_marked(struct sk_buff *skb);

/**
 * wifi_diag_tx_log_dbg - log tx result
 *
 * @local: ieee80211_local point to hw
 * @skb: ieee80211 frame
 * @result: ieee80211_tx_resultwifi_diag_set_rx_status
 * @driver: driver name
 */
void wifi_diag_tx_log_dbg(struct ieee80211_local *local,
			  struct sk_buff *skb,
			  ieee80211_tx_result result,
			  const char *driver,
			  const char *fmt, ...);

/**
 * wifi_diag_tx_status_log_dbg - log tx status
 *
 * @local: ieee80211_local point to hw
 * @skb: ieee80211 frame
 * @driver: driver name
 */
void wifi_diag_tx_status_log_dbg(struct ieee80211_local *local,
				 struct sk_buff *skb,
				 const char *driver,
				 const char *fmt, ...);

/**
 * wifi_diag_rx_status_log_dbg - log rx status
 *
 * @local: ieee80211_local point to hw
 * @skb: ieee80211 frame
 * @result: ieee80211_rx_result
 * @driver: driver name
 */
void wifi_diag_rx_status_log_dbg(struct ieee80211_local *local,
				 struct sk_buff *skb,
				 ieee80211_rx_result result,
				 const char *driver,
				 const char *fmt, ...);

#define WIFI_DIAG_SET_TX_INFO(local, sta, skb)				\
	do {								\
		if (WIFI_DIAG_ENABLED(local))				\
			wifi_diag_set_tx_info(local, sta, skb);		\
	} while (0)

#define WIFI_DIAG_SET_RX_STATUS(local, sta, skb)			\
	do {								\
		if (WIFI_DIAG_ENABLED(local))				\
			wifi_diag_set_rx_status(local, sta, skb);	\
	} while (0)

#define WIFI_DIAG_TX(skb)			\
	wifi_diag_rx_marked(skb)

#define WIFI_DIAG_RX_STATUS(skb)		\
	wifi_diag_rx_marked(skb)

#define WIFI_DIAG_ENABLED(local)		\
	((local)->wifi_diag_enable && (local)->wifi_diag_config)

#define WIFI_DIAG_LOCAL_DRIVER_STRING(local)			\
	dev_driver_string(wiphy_dev((local)->hw.wiphy))

#define WIFI_DIAG_TX_DBG(tx, result, fmt, ...)			\
	do {								\
		const char *name;					\
		if (!WIFI_DIAG_ENABLED((tx)->local))			\
			break;						\
		name = (tx)->sdata ? (tx)->sdata->name			\
			: WIFI_DIAG_LOCAL_DRIVER_STRING((tx)->local);	\
		wifi_diag_tx_log_dbg((tx)->local, (tx)->skb, result,	\
					name, fmt, ##__VA_ARGS__);	\
	} while (0)

#define WIFI_DIAG_TX_SDATA_DBG(sdata, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!WIFI_DIAG_ENABLED((sdata)->local))			\
			break;						\
		name = (sdata)->name;					\
		wifi_diag_tx_log_dbg((sdata)->local, skb, result,	\
					name, fmt, ##__VA_ARGS__);	\
	} while (0)

#define WIFI_DIAG_TX_LOCAL_DBG(local, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!WIFI_DIAG_ENABLED(local))				\
			break;						\
		name = WIFI_DIAG_LOCAL_DRIVER_STRING(local);		\
		wifi_diag_tx_log_dbg(local, skb, result,		\
					name, fmt, ##__VA_ARGS__);	\
	} while (0)

#define WIFI_DIAG_TX_STATUS_SDATA_DBG(sdata, skb, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!WIFI_DIAG_ENABLED((sdata)->local))			\
			break;						\
		name = (sdata)->name;					\
		wifi_diag_tx_status_log_dbg((sdata)->local, skb,	\
						name,			\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define WIFI_DIAG_TX_STATUS_LOCAL_DBG(local, skb, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!WIFI_DIAG_ENABLED(local))				\
			break;						\
		name = WIFI_DIAG_LOCAL_DRIVER_STRING(local);		\
		wifi_diag_tx_status_log_dbg(local, skb,			\
						name,			\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define WIFI_DIAG_RX_DBG(rx, result, fmt, ...)				\
	do {								\
		const char *name;					\
		if (!WIFI_DIAG_ENABLED((rx)->local))			\
			break;						\
		name = (rx)->sdata ? (rx)->sdata->name			\
			: WIFI_DIAG_LOCAL_DRIVER_STRING((rx)->local);	\
		wifi_diag_rx_status_log_dbg((rx)->local, (rx)->skb,	\
						result, name,		\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define WIFI_DIAG_RX_SDATA_DBG(sdata, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!WIFI_DIAG_ENABLED((sdata)->local))			\
			break;						\
		name = (sdata)->name;					\
		wifi_diag_rx_status_log_dbg((sdata)->local, skb,	\
						result, name,		\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#define WIFI_DIAG_RX_LOCAL_DBG(local, skb, result, fmt, ...)		\
	do {								\
		const char *name;					\
		if (!WIFI_DIAG_ENABLED(local))				\
			break;						\
		name = WIFI_DIAG_LOCAL_DRIVER_STRING(local);		\
		wifi_diag_rx_status_log_dbg(local, skb,			\
						result, name,		\
						fmt, ##__VA_ARGS__);	\
	} while (0)

#endif /* CONFIG_MAC80211_WIFI_DIAG */

#endif /* __MAC80211_WIFI_DIAG_H */

