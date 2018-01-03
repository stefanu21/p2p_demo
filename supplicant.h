#include "wpa_code_gen/wpa.h"
#include "wpa_code_gen/wpa_interface.h"
#include <gio/gio.h>

gint supplicant_set_wfdie(wpaFiW1Wpa_supplicant1 *proxy, guint port, guint max_throughput_mbps);
gint supplicant_set_primary_dev_type(wpainterfaceP2PDevice *proxy, gchar *device_name, guint go_intent);
gint supplicant_set_extended_listen(wpainterfaceP2PDevice *proxy, gint periode_ms, gint interval_ms);

GVariant *supplicant_create_connect_variant(const gchar *peer, gint go_intent, const gchar *wps_methode, bool join);
gchar *supplicant_create_interface_sync(wpaFiW1Wpa_supplicant1 *proxy, gchar *ifname);
