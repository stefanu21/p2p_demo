#include <stdbool.h>
#include <stdio.h>
#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>
#include "supplicant.h"
#include "common/log.h"

gint supplicant_set_wfdie(wpaFiW1Wpa_supplicant1 *proxy, guint port, guint max_throughput_mbps)
{
	/*
	 * [0] SubElement ID WFD Device Information
	 * [1][2] SubElement body length
	 * [3][4] WFD Device Information - 0x01 primary Sink, 0x10 Available for WFD Session
	 * [5][6] Session Management TCP Control Port (default 7236)
	 * [7][8] WFD Device Maximum Avarage Throughput Capability (multiple of 1Mbps)
	 *
	 * see Wi-Fi Display Technical Specification Version 2.1 Page 81 (Table28 and TAble 29)
	 */

	const gchar wfdie[] =
	{ 0x00, 0x00, 0x06, 0x00, 0x11, port >> 8,
			port & 0xFF, max_throughput_mbps >> 8,
			max_throughput_mbps };
	GVariantBuilder *variant_builder = g_variant_builder_new(G_VARIANT_TYPE ("ay"));
	GVariant *variant;
	gint i;

	if(!variant_builder)
	{
		logg_err("create variant builder error");
		return -1;
	}

	for (i = 0; i < ARRAYSIZE(wfdie) ; i++)
		g_variant_builder_add (variant_builder, "y", wfdie[i]);

	variant = g_variant_builder_end (variant_builder);

	g_variant_builder_unref (variant_builder);

	wpa_fi_w1_wpa_supplicant1_set_wfdies(proxy, variant);
	return 0;
}

gint supplicant_set_primary_dev_type(wpainterfaceP2PDevice *proxy,
		gchar *device_name, guint go_intent)
{
	/*
	 * [0][1] Category ID 0x01 = Computer
	 * [2][3][4][5] OUI default for Wifi Alliance 0x00 0x50 0xf2 0x04
	 * [6][7] Sub Category Id 0x05 = Notebook
	 *
	 * See Table 41 (Primary Device Type) in Section 12 (Data Element Definitions) of the Wi-Fi  Simple Configuration specification
	 */

	const guchar PrimaryDeviceType[] =
	{ 0x00, 0x01, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x05 };
	GVariantBuilder *variant_builder = g_variant_builder_new(
			G_VARIANT_TYPE ("ay"));
	GVariant *variant;
	gint i;

	for (i = 0; i < ARRAYSIZE(PrimaryDeviceType); i++)
		g_variant_builder_add(variant_builder, "y", PrimaryDeviceType[i]);

	variant = g_variant_builder_end(variant_builder);
	g_variant_builder_unref(variant_builder);

	variant_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	g_variant_builder_add(variant_builder, "{sv}", "DeviceName",
			g_variant_new("s", device_name));
	g_variant_builder_add(variant_builder, "{sv}", "PrimaryDeviceType",
			variant);

	g_variant_builder_add(variant_builder, "{sv}", "GOIntent",
			g_variant_new("u", go_intent));
//g_variant_builder_add (variant_builder, "{sv}", "PersistentReconnect", g_variant_new("b", false));
//g_variant_builder_add (variant_builder, "{sv}", "ListenRegClass", g_variant_new("u", 0));
//g_variant_builder_add (variant_builder, "{sv}", "ListenChannel", g_variant_new("u", 0));
//g_variant_builder_add (variant_builder, "{sv}", "OperRegClass", g_variant_new("u", 0));
//g_variant_builder_add (variant_builder, "{sv}", "OperChannel", g_variant_new("u", 0));
//g_variant_builder_add (variant_builder, "{sv}", "IntraBss", g_variant_new("b", true));
//g_variant_builder_add (variant_builder, "{sv}", "GroupIdle", g_variant_new("u", 0));
//g_variant_builder_add (variant_builder, "{sv}", "disassoc_low_ack", g_variant_new("u", 0));
//g_variant_builder_add (variant_builder, "{sv}", "NoGroupIface", g_variant_new("b", false));
//g_variant_builder_add (variant_builder, "{sv}", "p2p_search_delay", g_variant_new("u", 500));

	variant = g_variant_builder_end(variant_builder);

	g_variant_builder_unref(variant_builder);

	wpa_interface_p2_pdevice_set_p2_pdevice_config(proxy, variant);

	return 0;
}

gint supplicant_set_extended_listen(wpainterfaceP2PDevice *proxy,
		gint periode_ms, gint interval_ms)
{
	GVariantBuilder *variant_builder = g_variant_builder_new(
			G_VARIANT_TYPE ("a{sv}"));
	GVariant *variant;
	GError *err = NULL;

	g_variant_builder_add(variant_builder, "{sv}", "period",
			g_variant_new("i", periode_ms));
	g_variant_builder_add(variant_builder, "{sv}", "interval",
			g_variant_new("i", interval_ms));

	variant = g_variant_builder_end(variant_builder);

	g_variant_builder_unref(variant_builder);

	if (!wpa_interface_p2_pdevice_call_extended_listen_sync(proxy, variant,
			NULL, &err) || err)
	{
		logg_err("Error call ext listen %s", err->message);
		g_error_free(err);
		return -1;
	}

	return 0;
}

gchar *supplicant_create_interface_sync(wpaFiW1Wpa_supplicant1 *proxy, gchar *ifname)
{
	GVariantBuilder *variant_builder = g_variant_builder_new(
			G_VARIANT_TYPE ("a{sv}"));
	GVariant *variant;
	GError *err = NULL;
	gchar *iface = NULL;

	g_variant_builder_add(variant_builder, "{sv}", "Ifname",
			g_variant_new("s", ifname));
	g_variant_builder_add(variant_builder, "{sv}", "Driver",
			g_variant_new("s", "nl80211,wext"));

	variant = g_variant_builder_end(variant_builder);

	g_variant_builder_unref(variant_builder);

	if (!wpa_fi_w1_wpa_supplicant1_call_create_interface_sync(proxy, variant,
			&iface, NULL, &err) || err)
	{
		logg_err("error create interface for %s: %s", ifname, err->message);
		g_error_free(err);
		return NULL;
	}
	return iface;
}

GVariant *supplicant_create_connect_variant(const gchar *peer, gint go_intent, const gchar *wps_methode, bool join)
{
	GVariantBuilder *variant_builder = g_variant_builder_new(
			G_VARIANT_TYPE ("a{sv}"));
	GVariant *variant;

	g_variant_builder_add(variant_builder, "{sv}", "peer",
			g_variant_new("o", peer));
	g_variant_builder_add(variant_builder, "{sv}", "persistent",
			g_variant_new("b", true));
	g_variant_builder_add(variant_builder, "{sv}", "join",
			g_variant_new("b", join));
	g_variant_builder_add(variant_builder, "{sv}", "go_intent",
			g_variant_new("i", go_intent));
	g_variant_builder_add(variant_builder, "{sv}", "wps_method",
			g_variant_new("s", wps_methode));

	variant = g_variant_builder_end(variant_builder);

	g_variant_builder_unref(variant_builder);

	return variant;
}
