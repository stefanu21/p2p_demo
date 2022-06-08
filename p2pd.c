#include "ap_mode.h"
#include "common.h"
#include "group.h"
#include "interface.h"
#include "wpa.h"
#include "wpa_interface.h"
#include "wpa_peer.h"

#define CLIENTNAME "p2pd"

static gint
set_wfdie(WpaSupplicant *proxy, guint port, guint max_throughput_mbps)
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

  const gchar wfdie[] = { 0x00,
                          0x00,
                          0x06,
                          0x00,
                          0x11,
                          port >> 8,
                          port & 0xFF,
                          max_throughput_mbps >> 8,
                          max_throughput_mbps };
  GVariantBuilder *variant_builder = g_variant_builder_new(G_VARIANT_TYPE("ay"));
  GVariant *variant;
  gint i;

  if (!variant_builder) {
    logg_err("create variant builder error");
    return -1;
  }

  for (i = 0; i < ARRAYSIZE(wfdie); i++)
    g_variant_builder_add(variant_builder, "y", wfdie[i]);

  variant = g_variant_builder_end(variant_builder);

  g_variant_builder_unref(variant_builder);

  wpa_supplicant__set_wfdies(proxy, variant);
  return 0;
}

extern struct wpa_interface_p2p_signals_cb_t client_mode_p2p_callbacks;

static gint
switch_wlan_mode(struct wpa_t *obj, int scan_ap_list)
{
  gchar *iface_obj_str = NULL;

  iface_obj_str = interface_create_sync(P2P_MAIN_WLAN_INTERFACE, obj);

  if (!iface_obj_str) {
    logg_err("can't create new interface");
    return -1;
  }

  set_wfdie(obj->wpa_proxy, RTSP_TCP_CONTROL_PORT, DEV_MAX_AVERABE_THROUGHPUT_MBPS);

    obj->iface_obj = interface_obj_new(iface_obj_str, NULL,
                                       &ap_mode_p2p_callbacks, NULL, obj); 

    if (!obj->iface_obj) {
      logg_err("can't create new ap interface");
      return -1;
    }

    interface_connect_group(obj, NULL, 0);

  g_free(iface_obj_str);
  return 0;
}

int
main(int argn, char *argv[])
{
  g_autoptr(GError) err = NULL;
  struct wpa_t wpa_obj = { 0 };

  snprintf(wpa_obj.miracast.device_name, sizeof(wpa_obj.miracast.device_name), "NUC8_TEST_DEVICE");
  wpa_obj.g_main_loop = g_main_loop_new(NULL, false);
  wpa_obj.dbus_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);

  if (err) {
    logg_err("Failed to acquire connection: %s", err->message);
    return 0;
  }

  wpa_obj.wpa_proxy = wpa_supplicant__proxy_new_sync(wpa_obj.dbus_connection,
                                                     G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME,
                                                     WPA_SUP_PATH, NULL, &err);

  if (err) {
    logg_err("get wpa_proxy error %s", err->message);
    return 0; 
  }

  gchar *iface_obj_str = interface_get_interface_obj_str_sync(wpa_obj.wpa_proxy,
                                                              P2P_MAIN_WLAN_INTERFACE);

  if (iface_obj_str) {
    p2p_logg_dbg("remove interface " P2P_MAIN_WLAN_INTERFACE " %s", iface_obj_str);
    interface_remove_interface_by_obj_str(wpa_obj.wpa_proxy, iface_obj_str);
    g_free(iface_obj_str);
  }

  iface_obj_str = interface_get_interface_obj_str_sync(wpa_obj.wpa_proxy,
                                                       P2P_VIRTUAL_WLAN_INTERFACE);

  if (iface_obj_str) {
    p2p_logg_dbg("remove interface " P2P_VIRTUAL_WLAN_INTERFACE ": %s", iface_obj_str);
    interface_remove_interface_by_obj_str(wpa_obj.wpa_proxy, iface_obj_str);
    g_free(iface_obj_str);
  }

  g_free(iface_obj_str);

  wpa_obj.wpa_signals_cb = NULL;

  wpa_signals_connect(&wpa_obj);

  switch_wlan_mode(&wpa_obj, 0);
  g_main_loop_run(wpa_obj.g_main_loop);

  wpa_signals_disconnect(&wpa_obj);

  return 0;
}
