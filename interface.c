#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "common.h"
#include "interface.h"

void
interface_set_extended_listen(WpaInterfaceP2PDevice *proxy, gint period_ms, gint interval_ms)
{
  GVariantBuilder variant_builder;
  GVariant *variant = NULL;
  g_autoptr(GError) err = NULL;

  p2p_logg_dbg("set extended listen %d/%d", period_ms, interval_ms);

  if (!proxy) {
    logg_err("proxy error");
    return;
  }

  g_variant_builder_init(&variant_builder, G_VARIANT_TYPE_VARDICT);

  if (period_ms)
    g_variant_builder_add(&variant_builder, "{sv}", "period", g_variant_new("i", period_ms));

  if (interval_ms)
    g_variant_builder_add(&variant_builder, "{sv}", "interval", g_variant_new("i", interval_ms));

  variant = g_variant_builder_end(&variant_builder);

  if (!wpa_interface_p2_pdevice_call_extended_listen_sync(proxy, variant, NULL, &err) || err)
    logg_err("P2P: Error call ext-listen %s", err ? err->message : "");
}

static void
wps_signals_connect(struct wpa_interface_t *wpa_interface)
{
  SIGNAL_CONNECT(wpa_interface->iface_wps_proxy, wpa_interface->wps_signals.credentials,
                 "credentials", wpa_interface->wps_signals_cb->credentials, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_wps_proxy, wpa_interface->wps_signals.event, "event",
                 wpa_interface->wps_signals_cb->event, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_wps_proxy, wpa_interface->wps_signals.prop_changed,
                 "properties_changed", wpa_interface->wps_signals_cb->prop_changed, wpa_interface);
}

static void
wps_signals_disconnect(struct wpa_interface_t *wpa_interface)
{
  SIGNAL_DISCONNECT(wpa_interface->iface_wps_proxy, wpa_interface->wps_signals.credentials);
  SIGNAL_DISCONNECT(wpa_interface->iface_wps_proxy, wpa_interface->wps_signals.event);
  SIGNAL_DISCONNECT(wpa_interface->iface_wps_proxy, wpa_interface->wps_signals.prop_changed);
}

static void
interface_signals_connect(struct wpa_interface_t *wpa_interface)
{
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.sta_authorized,
                 "sta_authorized", wpa_interface->iface_signals_cb->sta_authorized, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.sta_deauthorized,
                 "sta_deauthorized", wpa_interface->iface_signals_cb->sta_deauthorized,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.bss_added, "bssadded",
                 wpa_interface->iface_signals_cb->bss_added, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.bss_removed, "bssremoved",
                 wpa_interface->iface_signals_cb->bss_removed, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.scan_done, "scan_done",
                 wpa_interface->iface_signals_cb->scan_done, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.network_added,
                 "network_added", wpa_interface->iface_signals_cb->network_added, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.network_removed,
                 "network_removed", wpa_interface->iface_signals_cb->network_removed,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.network_selected,
                 "network_selected", wpa_interface->iface_signals_cb->network_selected,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.eap, "eap",
                 wpa_interface->iface_signals_cb->eap, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.network_request,
                 "network_request", wpa_interface->iface_signals_cb->network_request,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.properties_changed,
                 "properties_changed", wpa_interface->iface_signals_cb->properties_changed,
                 wpa_interface);
}

static void
interface_signals_disconnect(struct wpa_interface_t *wpa_interface)
{
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.sta_deauthorized);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.scan_done);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.sta_authorized);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.bss_added);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.bss_removed);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.network_added);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.network_removed);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.network_request);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.network_selected);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.eap);
  SIGNAL_DISCONNECT(wpa_interface->iface_proxy, wpa_interface->iface_signals.properties_changed);
}

static void
interface_p2p_signals_connect(struct wpa_interface_t *wpa_interface)
{
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.dev_found,
                 "device_found", wpa_interface->p2p_signals_cb->device_found, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.dev_found_prop,
                 "device_found_properties", wpa_interface->p2p_signals_cb->device_found_properties,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.dev_lost, "device_lost",
                 wpa_interface->p2p_signals_cb->device_lost, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.find_stopped,
                 "find_stopped", wpa_interface->p2p_signals_cb->find_stopped, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.group_started,
                 "group_started", wpa_interface->p2p_signals_cb->group_started, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.group_formation_failure,
                 "group_formation_failure", wpa_interface->p2p_signals_cb->group_formation_failure,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.group_finished,
                 "group_finished", wpa_interface->p2p_signals_cb->group_finished, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.gonegotiation_failure,
                 "gonegotiation_failure", wpa_interface->p2p_signals_cb->gonegotiation_failure,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.gonegotiation_request,
                 "gonegotiation_request", wpa_interface->p2p_signals_cb->gonegotiation_request,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.gonegotiation_success,
                 "gonegotiation_success", wpa_interface->p2p_signals_cb->gonegotiation_success,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.wps_failed,
                 "wps_failed", wpa_interface->p2p_signals_cb->wps_failed, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.service_discovery_request, "service_discovery_request",
                 wpa_interface->p2p_signals_cb->service_discovery_request, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.service_discovery_response,
                 "service_discovery_response",
                 wpa_interface->p2p_signals_cb->service_discovery_response, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.provision_discovery_response_enter_pin,
                 "provision_discovery_response_enter_pin",
                 wpa_interface->p2p_signals_cb->provision_discovery_response_enter_pin,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.provision_discovery_response_display_pin,
                 "provision_discovery_response_display_pin",
                 wpa_interface->p2p_signals_cb->provision_discovery_response_display_pin,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.provision_discovery_request_enter_pin,
                 "provision_discovery_request_enter_pin",
                 wpa_interface->p2p_signals_cb->provision_discovery_request_enter_pin,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.provision_discovery_request_display_pin,
                 "provision_discovery_request_display_pin",
                 wpa_interface->p2p_signals_cb->provision_discovery_request_display_pin,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.provision_discovery_pbcresponse,
                 "provision_discovery_pbcresponse",
                 wpa_interface->p2p_signals_cb->provision_discovery_pbcresponse, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.provision_discovery_pbcrequest,
                 "provision_discovery_pbcrequest",
                 wpa_interface->p2p_signals_cb->provision_discovery_pbcrequest, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.provision_discovery_failure,
                 "provision_discovery_failure",
                 wpa_interface->p2p_signals_cb->provision_discovery_failure, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy,
                 wpa_interface->p2p_signals.persistent_group_removed, "persistent_group_removed",
                 wpa_interface->p2p_signals_cb->persistent_group_removed, wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.persistent_group_added,
                 "persistent_group_added", wpa_interface->p2p_signals_cb->persistent_group_added,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.invitation_result,
                 "invitation_result", wpa_interface->p2p_signals_cb->invitation_result,
                 wpa_interface);
  SIGNAL_CONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.invitation_received,
                 "invitation_received", wpa_interface->p2p_signals_cb->invitation_received,
                 wpa_interface);
}

void
interface_p2p_signals_disconnect(struct wpa_interface_t *wpa_interface)
{
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.dev_found);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.dev_found_prop);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.dev_lost);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.find_stopped);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.gonegotiation_failure);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.gonegotiation_request);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.gonegotiation_success);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.group_finished);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.group_formation_failure);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.group_started);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.invitation_received);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.invitation_result);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.persistent_group_added);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.persistent_group_removed);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.provision_discovery_failure);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.provision_discovery_pbcrequest);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.provision_discovery_pbcresponse);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.provision_discovery_request_display_pin);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.provision_discovery_request_enter_pin);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.provision_discovery_response_display_pin);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.provision_discovery_response_enter_pin);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.service_discovery_request);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy,
                    wpa_interface->p2p_signals.service_discovery_response);
  SIGNAL_DISCONNECT(wpa_interface->iface_p2p_proxy, wpa_interface->p2p_signals.wps_failed);
}

gchar *
interface_create_sync(gchar *ifname, struct wpa_t *obj)
{
  GVariantBuilder *variant_builder;
  GVariant *variant;
  GError *err = NULL;
  gchar *obj_str = NULL;

  variant_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

  g_variant_builder_add(variant_builder, "{sv}", "Ifname", g_variant_new("s", ifname));
  g_variant_builder_add(variant_builder, "{sv}", "Driver", g_variant_new("s", "nl80211,wext"));
  variant = g_variant_builder_end(variant_builder);

  g_variant_builder_unref(variant_builder);

  if (!wpa_supplicant__call_create_interface_sync(obj->wpa_proxy, variant, &obj_str, NULL, &err) ||
      err) {
    logg_err("error create interface for %s: %s", ifname, err->message);
    g_error_free(err);
    return NULL;
  }

  return obj_str;
}

static gint
set_p2p_device_config(WpaInterfaceP2PDevice *proxy, struct miracast_obj_t *miracast)
{
  /*
   * [0][1] Category ID 0x07 = Display (some devices e.g. Lumia 640 (Windows Phone 8.1 Update 2)
   * only show display devices) [2][3][4][5] OUI default for Wifi Alliance 0x00 0x50 0xf2 0x04
   * [6][7] Sub Category Id 0x04 = Monitor
   *
   * See Table 41 (Primary Device Type) in Section 12 (Data Element Definitions) of the Wi-Fi Simple
   * Configuration specification
   */

  const guchar PrimaryDeviceType[] = { 0x00, 0x07, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x04 };

  GVariantBuilder *variant_builder = g_variant_builder_new(G_VARIANT_TYPE("ay"));
  GVariant *variant;
  gint i;

  p2p_logg_dbg("name: %s, intent: %d", miracast->device_name, GO_INTENT );

  for (i = 0; i < ARRAYSIZE(PrimaryDeviceType); i++)
    g_variant_builder_add(variant_builder, "y", PrimaryDeviceType[i]);

  variant = g_variant_builder_end(variant_builder);
  g_variant_builder_unref(variant_builder);

  variant_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

  g_variant_builder_add(variant_builder, "{sv}", "DeviceName",
                        g_variant_new("s", miracast->device_name));
  g_variant_builder_add(variant_builder, "{sv}", "PrimaryDeviceType", variant);

  g_variant_builder_add(variant_builder, "{sv}", "GOIntent",
                        g_variant_new("u", GO_INTENT));
  g_variant_builder_add(variant_builder, "{sv}", "PersistentReconnect", g_variant_new("b", true));

  variant = g_variant_builder_end(variant_builder);

  g_variant_builder_unref(variant_builder);
  wpa_interface_p2_pdevice_set_p2_pdevice_config(proxy, variant);
  return 0;
}

struct wpa_interface_t *
interface_obj_new(gchar *obj_str,
                  struct wpa_interface_iface_signals_cb_t *iface_signals_cb,
                  struct wpa_interface_p2p_signals_cb_t *iface_p2p_signals_cb,
		  struct wpa_interface_wps_signals_cb_t *wps_signals_cb, struct wpa_t *obj)
{
  GError *err = NULL;
  struct wpa_interface_t *wpa_interface;
  WpaInterface *iface_proxy;

  iface_proxy = wpa_interface__proxy_new_sync(obj->dbus_connection, G_DBUS_PROXY_FLAGS_NONE,
                                              WPA_SUP_NAME, obj_str, NULL, &err);

  if (err) {
    logg_err("error proxy interface create for %s: %s", obj_str, err->message);
    g_error_free(err);
    return NULL;
  }

  wpa_interface = g_try_new0(struct wpa_interface_t, 1);

  wpa_interface->iface_proxy = iface_proxy;
  wpa_interface->obj_str = g_strdup(obj_str);
  wpa_interface->ifname = wpa_interface__dup_ifname(iface_proxy);
  wpa_interface->wpa_obj = obj;

  if (iface_signals_cb) {
    wpa_interface->iface_signals_cb = iface_signals_cb;
    interface_signals_connect(wpa_interface);
  }

  wpa_interface->iface_wps_proxy = wpa_interface_wps_proxy_new_sync(obj->dbus_connection,
                                                                    G_DBUS_PROXY_FLAGS_NONE,
                                                                    WPA_SUP_NAME, obj_str, NULL,
                                                                    &err);
  wpa_interface->iface_p2p_proxy = wpa_interface_p2_pdevice_proxy_new_sync(obj->dbus_connection,
                                                                           G_DBUS_PROXY_FLAGS_NONE,
                                                                           WPA_SUP_NAME, obj_str,
                                                                           NULL, &err);

  if (iface_p2p_signals_cb) {
    wpa_interface->p2p_signals_cb = iface_p2p_signals_cb;
    interface_p2p_signals_connect(wpa_interface);
  }

  if (wps_signals_cb) {
    wpa_interface->wps_signals_cb = wps_signals_cb;
    wps_signals_connect(wpa_interface);
  }

  set_p2p_device_config(wpa_interface->iface_p2p_proxy, &obj->miracast);
  wpa_interface_wps_set_config_methods(wpa_interface->iface_wps_proxy, "push_button");

  return wpa_interface;
}

gint
interface_obj_destroy(WpaSupplicant *proxy, struct wpa_interface_t *wpa_interface)
{
  if (!wpa_interface)
    return -1;

  group_remove_group_obj_from_interface(wpa_interface);

  interface_remove_interface_by_obj_str(proxy, wpa_interface->obj_str);

  g_free(wpa_interface->ifname);
  g_free(wpa_interface->obj_str);

  if (wpa_interface->iface_signals_cb)
    interface_signals_disconnect(wpa_interface);

  if (wpa_interface->p2p_signals_cb)
    interface_p2p_signals_disconnect(wpa_interface);

  if (wpa_interface->wps_signals_cb)
    wps_signals_disconnect(wpa_interface);

  g_object_unref(wpa_interface->iface_p2p_proxy);
  g_object_unref(wpa_interface->iface_wps_proxy);
  g_object_unref(wpa_interface->iface_proxy);

  g_free(wpa_interface);
  return 0;
}
static int
is_alphanumeric(char digit)
{
  if (((digit >= 'a') && (digit <= 'z')) || ((digit >= 'A') && (digit <= 'Z')) ||
      ((digit >= '0') && (digit <= '9')))
    return 1;
  else
    return 0;
}

char *
toolbox_random_string(unsigned len, int alphanumeric_only)
{
  char *str = NULL, r_digit;
  int x = 0;
  struct timeval time;
  FILE *urandom;

  str = malloc(len + 1);
  if (!str)
    return NULL;

  if ((urandom = fopen("/dev/urandom", "r")) != NULL) {
    while (x < len) {
      if (fread(&r_digit, sizeof(char), 1, urandom) == 1) {   
        if (!alphanumeric_only || (is_alphanumeric(r_digit))) {
          str[x] = r_digit;
          x++;
        }
      }
    }
    fclose(urandom);
  } else {
    if (gettimeofday(&time, NULL) == -1)
      return 0;

    srand((time.tv_sec * 1000) + (time.tv_usec / 1000));
    while (x < len) {
      r_digit = rand() % 255;
      if (!alphanumeric_only || (is_alphanumeric(r_digit))) {
        str[x] = r_digit;
        x++;
      }
    }
  }
  str[len] = '\0';
  return str;
}

gint
interface_connect_group(struct wpa_t *obj, const gchar *ssid, gint frequency_mhz)
{
  struct wpa_interface_t *interface = obj->iface_obj;
  char *pers_group_path = NULL;
  g_autoptr(GError) err = NULL;
  GVariantBuilder variant_builder;
  GVariant *variant = NULL;

  if (ssid) {
    char direct_ssid[32];
    char *tmp = toolbox_random_string(4, 1);
    int ssid_max_len = sizeof(direct_ssid) - (strlen("DIRECT-wv-") + strlen(tmp) + 1);

    logg_err("ssid max: %d / %lu", ssid_max_len, strlen(ssid));
    snprintf(direct_ssid, sizeof(direct_ssid), "DIRECT-wv-%.*s-%s",
             strlen(ssid) > ssid_max_len ? ssid_max_len : (int) strlen(ssid), ssid, tmp);
    g_free(tmp);

    tmp = toolbox_random_string(8, 1);
    g_variant_builder_init(&variant_builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add(&variant_builder, "{sv}", "ssid", g_variant_new("s", direct_ssid));
    g_variant_builder_add(&variant_builder, "{sv}", "psk", g_variant_new("s", tmp));
    g_variant_builder_add(&variant_builder, "{sv}", "mode", g_variant_new("i", 3));
    g_free(tmp);
    variant = g_variant_builder_end(&variant_builder);
    wpa_interface_p2_pdevice_call_add_persistent_group_sync(interface->iface_p2p_proxy, variant,
                                                            &pers_group_path, NULL, &err);
  }

  g_variant_builder_init(&variant_builder, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add(&variant_builder, "{sv}", "persistent", g_variant_new("b", false));

  g_variant_builder_add(&variant_builder, "{sv}", "frequency", g_variant_new("i", 2412));
  if (pers_group_path) {
    g_variant_builder_add(&variant_builder, "{sv}", "persistent_group_object",
                          g_variant_new("o", pers_group_path));
    g_free(pers_group_path);
  }

  variant = g_variant_builder_end(&variant_builder);

  if (!wpa_interface_p2_pdevice_call_group_add_sync(interface->iface_p2p_proxy, variant, NULL,
                                                    &err) ||
      err) {
    logg_err("Error call add group %s", err ? err->message : "");
    return -1;
  }
  return 0;
}

gint
interface_disconnect_group(struct wpa_t *obj)
{
  struct wpa_interface_t *ap_interface = obj->ap_iface_obj;
  g_autoptr(GError) err = NULL;

  if (!ap_interface)
    return -1;

  if (!wpa_interface__call_disconnect_sync(ap_interface->iface_proxy, NULL, &err))
    logg_err("error disconnect: %s", err->message);

  group_remove_group_obj_from_interface(ap_interface);
  interface_obj_destroy(obj->wpa_proxy, ap_interface);
  obj->ap_iface_obj = NULL;
  return 0;
}

gint
interface_remove_interface_by_obj_str(WpaSupplicant *proxy, const gchar *iface_obj_str)
{
  GError *err = NULL;
  gint rc = 0;

  if (!wpa_supplicant__call_remove_interface_sync(proxy, iface_obj_str, NULL, &err) || err) {
    logg_err("error remove interface %s: %s", iface_obj_str, err->message);
    rc = -1;
    g_error_free(err);
  }

  return rc;
}

gchar *
interface_get_interface_obj_str_sync(WpaSupplicant *proxy, gchar *ifname)
{
  GError *err = NULL;
  gchar *if_obj_str;

  if (!wpa_supplicant__call_get_interface_sync(proxy, ifname, &if_obj_str, NULL, &err) || err) {
    logg_err("error remove interface %s: %s", ifname, err->message);
    g_error_free(err);
    return NULL;
  }

  return if_obj_str;
}
