#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "ap_mode.h"
#include "common.h"
#include "group.h"

struct peer_t {
  WpaPeer *proxy;
  gchar *obj_str;
  gchar *device_addr;
  gchar *mac;
  gchar *device_name;
  struct group_t *group;
};

static void
peer_obj_destroy(struct peer_t *peer)
{
  if (!peer)
    return;

  p2p_logg_dbg("destroy peer: %s", peer->obj_str);
  g_free(peer->device_addr);
  g_free(peer->device_name);
  g_free(peer->obj_str);
  g_free(peer->mac);
  g_object_unref(peer->proxy);
  g_free(peer);
}

static struct peer_t *
create_peer_obj_new(const char *obj_str, struct wpa_interface_t *interface)
{
  GVariant *tmp;
  struct peer_t *peer_obj;
  g_autoptr(GError) err = NULL;

  if (!obj_str || !interface)
    return NULL;

  if (!(peer_obj = calloc(1, sizeof(*peer_obj)))) {
    logg_err("alloc peer_obj error");
    return NULL;
  }

  peer_obj->proxy = wpa_peer__proxy_new_sync(interface->wpa_obj->dbus_connection,
                                             G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME, obj_str, NULL,
                                             &err);

  if (err) {
    logg_err("get peer proxy error %s", err->message);
    free(peer_obj);
    return NULL;
  }

  peer_obj->obj_str = g_strdup(obj_str);
  tmp = wpa_peer__get_device_address(peer_obj->proxy);

  if (tmp)
    peer_obj->device_addr = common_byte_array_to_string(tmp, TRUE);
  peer_obj->device_name = wpa_peer__dup_device_name(peer_obj->proxy);
  peer_obj->group = interface->group_obj;

  p2p_logg_info("peer: %s, Name: %s, MAC: %s", peer_obj->obj_str, peer_obj->device_name,
                peer_obj->device_addr);
  return peer_obj;
}

gboolean
search_peer_cb(gpointer key, gpointer value, gpointer user_data)
{
  const char *mac = (const char *) user_data;
  struct peer_t *peer = (struct peer_t *) value;

  p2p_logg_dbg("%s == %s", mac, peer->mac);
  if (!strcmp(mac, (const char *) peer->mac))
    return TRUE;

  return FALSE;
}

static gboolean
is_p2p_member(struct group_t *group, const gchar *mac)
{
  struct peer_t *peer;
  gboolean rc = FALSE;

  if (!group || !group->p2p_members_list)
    return FALSE;

  if (!g_hash_table_size(group->p2p_members_list)) {
    logg_err("list is empty");
    return FALSE;
  }

  p2p_logg_dbg("%s", mac);

  g_mutex_lock(&group->lock_member_list);
  {
    peer = (struct peer_t *) g_hash_table_find(group->p2p_members_list, search_peer_cb,
                                               (gpointer) mac);
    if (peer) {
      p2p_logg_info("%s is a p2p member", mac);
      rc = TRUE;
    }
  }
  g_mutex_unlock(&group->lock_member_list);
  return rc;
}

static void
interface_signal_sta_authorized_cb(WpaInterface *object, const gchar *arg_name, gpointer user_data)
{
  struct wpa_interface_t *wpa_interface = (struct wpa_interface_t *) user_data;

  p2p_logg_info("STA (MAC: %s) on interface %s", arg_name, wpa_interface->obj_str);

  if (wpa_interface->wpa_obj->ap_iface_obj && wpa_interface->wpa_obj->ap_iface_obj->group_obj) {
    struct group_t *group_obj = wpa_interface->wpa_obj->ap_iface_obj->group_obj;

    if (group_obj->joining_peer_obj_str) {
      g_mutex_lock(&group_obj->lock_member_list);
      {
        struct peer_t *peer = g_hash_table_lookup(group_obj->p2p_members_list,
                                                  group_obj->joining_peer_obj_str);
        logg_err("looking for peer add mac");
        peer->mac = g_strdup(arg_name);
      }
      g_mutex_unlock(&group_obj->lock_member_list);

      g_free(group_obj->joining_peer_obj_str);
      group_obj->joining_peer_obj_str = NULL;
    }
  }
}

static void
interface_signal_sta_deauthorized_cb(WpaInterface *object, const gchar *arg_name,
                                     gpointer user_data)
{
  struct wpa_interface_t *wpa_interface = (struct wpa_interface_t *) user_data;
  struct wpa_t *wpa_obj = (struct wpa_t *) wpa_interface->wpa_obj;

  if (is_p2p_member(wpa_obj->ap_iface_obj->group_obj, arg_name)) {
    p2p_logg_info("p2p client start miracast");
  }

  p2p_logg_info("STA (MAC: %s) on interface %s", arg_name, wpa_interface->obj_str);
}

struct wpa_interface_iface_signals_cb_t wpa_ap_iface_callbacks = {
  .properties_changed = NULL,
  .network_request = NULL,
  .eap = NULL,
  .network_selected = NULL,
  .network_removed = NULL,
  .network_added = NULL,
  .bss_removed = NULL,
  .scan_done = NULL,
  .sta_authorized = interface_signal_sta_authorized_cb,
  .bss_added = NULL,
  .sta_deauthorized = interface_signal_sta_deauthorized_cb,
};

static void
wps_signal_credentials(WpaInterfaceWPS *object, GVariant *arg_credentials, gpointer user_data)
{
  gchar *str = g_variant_print(arg_credentials, TRUE);
  p2p_logg_dbg("WPS: %s", str);
  g_free(str);
}

static void
wps_signal_event(WpaInterfaceWPS *object, const gchar *arg_name, GVariant *arg_args,
                 gpointer user_data)
{
  p2p_logg_dbg("%s", arg_name);
  gchar *str = g_variant_print(arg_args, TRUE);
  p2p_logg_dbg("WPS: %s", str);
  g_free(str);
}

static void
wps_signal_properties_changed(WpaInterfaceWPS *object, GVariant *arg_properties, gpointer user_data)
{
  gchar *str = g_variant_print(arg_properties, TRUE);
  p2p_logg_dbg("WPS: %s", str);
  g_free(str);
}

struct wpa_interface_wps_signals_cb_t wpa_ap_wps_cb = {
  .credentials = wps_signal_credentials,
  .prop_changed = wps_signal_properties_changed,
  .event = wps_signal_event,
};

static void
group_signal_peer_joined(WpaGroup *object, const gchar *arg_peer, gpointer user_data)
{
  g_autoptr(GError) err = NULL;
  struct group_t *group = (struct group_t *) user_data;
  struct peer_t *peer_obj;

  p2p_logg_info("%s", arg_peer);

  peer_obj = create_peer_obj_new(arg_peer, group->interface);

  if (!peer_obj || !peer_obj->device_addr) {
    logg_err("can't add peer_obj to p2p_member_list %p", peer_obj);
    return;
  }

  g_mutex_lock(&group->lock_member_list);
  {
    if (g_hash_table_replace(group->p2p_members_list, g_strdup(arg_peer), peer_obj))
      p2p_logg_dbg("add new peer to group member list");
    else
      logg_err("there is still a peer in the list");
  }
  g_mutex_unlock(&group->lock_member_list);

  group->joining_peer_obj_str = g_strdup(
    arg_peer); // hack because cannot find relation between peer device_addr and STA
}

static void
group_signal_peer_disconnected(WpaGroup *object, const gchar *arg_peer, gpointer user_data)
{
  g_autoptr(GError) err = NULL;
  struct group_t *group = (struct group_t *) user_data;

  if (group->joining_peer_obj_str && !strcmp(group->joining_peer_obj_str, arg_peer)) {
    logg_err("STA not connected");
    g_free(group->joining_peer_obj_str);
    group->joining_peer_obj_str = NULL;
  }
  p2p_logg_info("%s from group member list %s", arg_peer, group->obj_str);

  g_mutex_lock(&group->lock_member_list);
  {
    if (g_hash_table_remove(group->p2p_members_list, arg_peer))
      p2p_logg_dbg("peer %s removed from group member list", arg_peer);
  }
  g_mutex_unlock(&group->lock_member_list);
}

struct group_signals_cb_t group_signals_cb = {
  .peer_disconnected = group_signal_peer_disconnected,
  .peer_joined = group_signal_peer_joined,
};

static void
peer_obj_destroy_cb(void *user_data)
{
  peer_obj_destroy((struct peer_t *) user_data);
}

static void
p2p_signal_device_found(WpaInterfaceP2PDevice *object, const gchar *arg_path, gpointer user_data)
{
  // peer obj_path
  const gchar *interface = g_dbus_proxy_get_object_path(
    (GDBusProxy *) WPA_INTERFACE_P2_PDEVICE_PROXY(object));
  p2p_logg_dbg("P2P: interface %s", interface);
  p2p_logg_info("P2P: %s", arg_path);
}

static void
p2p_signal_device_found_properties(WpaInterfaceP2PDevice *object, const gchar *arg_path,
                                   GVariant *arg_properties, gpointer user_data)
{
  p2p_logg_dbg("P2P: %s", arg_path);
  gchar *str = g_variant_print(arg_properties, TRUE);
  p2p_logg_dbg("P2P: %s", str);
  g_free(str);
}

static void
p2p_signal_device_lost(WpaInterfaceP2PDevice *object, const gchar *arg_path, gpointer user_data)
{
  p2p_logg_info("P2P: %s", arg_path);
}

static void
p2p_signal_find_stopped(WpaInterfaceP2PDevice *object, gpointer user_data)
{
  p2p_logg_dbg("P2P: p2p_signal_find_stopped");
}

static void
p2p_signal_group_finished(WpaInterfaceP2PDevice *object, GVariant *arg_properties,
                          gpointer user_data)
{
  p2p_logg_info("P2P: p2p_signal_group_finished ");
}

int
toolbox_set_ip_address(const char *iface, const char *ip_addr, const char *subnetmask)
{
  struct ifreq ifr = { 0 };
  struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
  int rc = -1;
  int fd;

  if (!iface || !ip_addr || !subnetmask)
    return -1;

  fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  if (fd < 0) {
    logg_err("can't open socket");
    return -1;
  }

  snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);

  ifr.ifr_addr.sa_family = AF_INET;
  inet_pton(AF_INET, ip_addr, &addr->sin_addr);
  if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
    logg_err("error set ip-addr %s", ip_addr);
    goto end;
  }

  inet_pton(AF_INET, subnetmask, &addr->sin_addr);
  if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
    logg_err("error set subnetmask %s", subnetmask);
    goto end;
  }

  rc = 0;
end:
  close(fd);
  return rc;
}

static void
p2p_signal_group_started(WpaInterfaceP2PDevice *object, GVariant *arg_properties,
                         gpointer user_data)
{
  struct wpa_interface_t *wpa_interface = (struct wpa_interface_t *) user_data;
  struct wpa_interface_t *group_interface = NULL;
  GVariantIter iter;
  GVariant *value = NULL;

  gchar *key = NULL;
  gchar *role = NULL, *interface_obj_string = NULL, *group_obj_string = NULL;

  gchar *str = g_variant_print(arg_properties, TRUE);
  p2p_logg_dbg("P2P: %s", str);
  g_free(str);

  g_variant_iter_init(&iter, arg_properties);

  while (g_variant_iter_next(&iter, "{sv}", &key, &value)) {
    if (g_strcmp0(key, "interface_object") == 0)
      interface_obj_string = g_strdup(g_variant_get_string(value, NULL));

    if (g_strcmp0(key, "group_object") == 0)
      group_obj_string = g_strdup(g_variant_get_string(value, NULL));

    if (g_strcmp0(key, "role") == 0)
      role = g_strdup(g_variant_get_string(value, NULL));

    g_variant_unref(value);
    g_free(key);

    if (interface_obj_string && group_obj_string && role)
      break;
  }

  p2p_logg_info("P2P: iface: %s (%s)", interface_obj_string, wpa_interface->obj_str);
  p2p_logg_info("P2P: group_obj: %s", group_obj_string);
  p2p_logg_info("P2P: role %s", role);

  wpa_interface->wpa_obj->ap_iface_obj = interface_obj_new(interface_obj_string,
                                                           &wpa_ap_iface_callbacks, NULL,
                                                           &wpa_ap_wps_cb, wpa_interface->wpa_obj);
  group_interface = wpa_interface->wpa_obj->ap_iface_obj;

  group_add_group_obj_to_interface(group_interface, group_obj_string, &group_signals_cb, g_free,
                                   peer_obj_destroy_cb);

  toolbox_set_ip_address(group_interface->ifname, LOCAL_ADDR, LOCAL_SUBNETMASK);

  g_free(role);
  g_free(interface_obj_string);
  g_free(group_obj_string);
}

static void
p2p_signal_provision_discovery_failure(WpaInterfaceP2PDevice *object, const gchar *arg_peer_object,
                                       gint arg_status, gpointer user_data)
{
  logg_err("P2P: %s; Status: %d", arg_peer_object, arg_status);
}

static void
wps_start(GDBusConnection *dbus_connection, const gchar *group_interface_obj_string,
          const char *pin, const char *peer_obj_string)
{
  GVariantBuilder *variant_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
  GVariant *variant = NULL, *variant_ret;
  GError *err = NULL;
  WpaInterfaceWPS *prox_wps;
  WpaPeer *proxy_peer = NULL;
  GVariant *device_addr = NULL;

  proxy_peer = wpa_peer__proxy_new_sync(dbus_connection, G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME,
                                        peer_obj_string, NULL, &err);

  if (err) {
    logg_err("WPS: get iface peer_proxy error %s", err->message);
    g_error_free(err);
    return;
  }

  device_addr = wpa_peer__get_device_address(proxy_peer);

  prox_wps = wpa_interface_wps_proxy_new_sync(dbus_connection, G_DBUS_PROXY_FLAGS_NONE,
                                              WPA_SUP_NAME, group_interface_obj_string, NULL, &err);

  if (err) {
    logg_err("WPS: get iface wps_proxy error %s", err->message);
    g_error_free(err);
    g_object_unref(proxy_peer);
    return;
  }

  p2p_logg_info("WPS: interface %s (Pin: %s , Role: GO)", group_interface_obj_string,
                (pin && pin[0] != '\0') ? pin : "0000");

  wpa_interface_wps_set_config_methods(prox_wps,
                                       (pin && pin[0] != '\0') ? "display" : "push_button");

  g_variant_builder_add(variant_builder, "{sv}", "Role", g_variant_new("s", "registrar"));
  g_variant_builder_add(variant_builder, "{sv}", "Type", g_variant_new("s", pin ? "pin" : "pbc"));
  g_variant_builder_add(variant_builder, "{sv}", "Pin", g_variant_new("s", pin ? pin : "0000"));
  if (device_addr)
    g_variant_builder_add(variant_builder, "{sv}", "P2PDeviceAddress", device_addr);
  else
    logg_err("WPS: error set P2PDeviceAddress");

  variant = g_variant_builder_end(variant_builder);

  g_variant_builder_unref(variant_builder);

  gchar *str = g_variant_print(variant, TRUE);
  p2p_logg_dbg("WPS: Payload: %s", str);
  g_free(str);

  if (!wpa_interface_wps_call_start_sync(prox_wps, variant, &variant_ret, NULL, &err) || err) {
    logg_err("WPS: error create wps start call: %s", err ? err->message : "");
    if (err)
      g_error_free(err);
  } else {
    gchar *str = g_variant_print(variant_ret, TRUE);
    p2p_logg_dbg("WPS: Answer: %s", str);
    g_free(str);
  }
  g_variant_unref(variant_ret);
  g_object_unref(proxy_peer);
  g_object_unref(prox_wps);
  return;
}

static void
p2p_signal_provision_discovery_pbcrequest(WpaInterfaceP2PDevice *object,
                                          const gchar *arg_peer_object, gpointer user_data)
{
  struct wpa_interface_t *interface = (struct wpa_interface_t *) user_data;
  struct wpa_interface_t *ap_interface = interface->wpa_obj->ap_iface_obj;

  p2p_logg_info("P2P: %s", arg_peer_object);

  if (ap_interface && ap_interface->obj_str)
    wps_start(interface->wpa_obj->dbus_connection, ap_interface->obj_str, NULL, arg_peer_object);
}

static void
p2p_signal_provision_discovery_pbcresponse(WpaInterfaceP2PDevice *object,
                                           const gchar *arg_peer_object, gpointer user_data)
{
  p2p_logg_info("P2P: %s", arg_peer_object);
}

static void
p2p_signal_provision_discovery_request_display_pin(WpaInterfaceP2PDevice *object,
                                                   const gchar *arg_peer_object,
                                                   const gchar *arg_pin, gpointer user_data)
{
}

static void
p2p_signal_provision_discovery_response_display_pin(WpaInterfaceP2PDevice *object,
                                                    const gchar *arg_peer_object,
                                                    const gchar *arg_pin, gpointer user_data)
{
  p2p_logg_info("P2P: %s; Pin: %s", arg_peer_object, arg_pin);
}

static void
p2p_signal_wps_failed(WpaInterfaceP2PDevice *object, const gchar *arg_name, GVariant *arg_args,
                      gpointer user_data)
{
  logg_err("P2P: %s", arg_name);
  gchar *str = g_variant_print(arg_args, TRUE);
  p2p_logg_dbg("P2P: %s", str);
  g_free(str);
}

static void
p2p_signal_group_formation_failure(WpaInterfaceP2PDevice *object, const gchar *arg_reason,
                                   gpointer user_data)
{
  logg_err("P2P: %s", arg_reason);
}

struct wpa_interface_p2p_signals_cb_t ap_mode_p2p_callbacks = {
  .device_found = p2p_signal_device_found,
  .device_found_properties = p2p_signal_device_found_properties,
  .device_lost = p2p_signal_device_lost,
  .find_stopped = p2p_signal_find_stopped,
  .gonegotiation_failure = NULL,
  .gonegotiation_request = NULL,
  .gonegotiation_success = NULL,
  .group_finished = p2p_signal_group_finished,
  .group_formation_failure = p2p_signal_group_formation_failure,
  .group_started = p2p_signal_group_started,
  .invitation_received = NULL,
  .invitation_result = NULL,
  .persistent_group_added = NULL,
  .persistent_group_removed = NULL,
  .provision_discovery_failure = p2p_signal_provision_discovery_failure,
  .provision_discovery_pbcrequest = p2p_signal_provision_discovery_pbcrequest,
  .provision_discovery_pbcresponse = p2p_signal_provision_discovery_pbcresponse,
  .provision_discovery_request_display_pin = p2p_signal_provision_discovery_request_display_pin,
  .provision_discovery_request_enter_pin = NULL,
  .provision_discovery_response_display_pin = p2p_signal_provision_discovery_response_display_pin,
  .provision_discovery_response_enter_pin = NULL,
  .service_discovery_request = NULL,
  .service_discovery_response = NULL,
  .wps_failed = p2p_signal_wps_failed,
};
