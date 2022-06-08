#include "group.h"

static void
group_signals_connect(struct group_t *group)
{
  if (!group->signals_cb)
    return;

  SIGNAL_CONNECT(group->proxy, group->signals.peer_disconnected, "peer_disconnected",
                 group->signals_cb->peer_disconnected, group);
  SIGNAL_CONNECT(group->proxy, group->signals.peer_joined, "peer_joined",
                 group->signals_cb->peer_joined, group);
}

static void
group_signals_disconnect(struct group_t *group)
{
  if (!group->signals_cb)
    return;

  SIGNAL_DISCONNECT(group->proxy, group->signals.peer_disconnected);
  SIGNAL_DISCONNECT(group->proxy, group->signals.peer_joined);
}

void
group_remove_group_obj_from_interface(struct wpa_interface_t *interface_obj)
{
  if (!interface_obj || !interface_obj->group_obj)
    return;

  group_signals_disconnect(interface_obj->group_obj);
  g_free(interface_obj->group_obj->obj_str);
  g_free(interface_obj->group_obj->passphrase);
  g_free(interface_obj->group_obj->ssid);

  g_mutex_lock(&interface_obj->group_obj->lock_member_list);
  {
    g_hash_table_remove_all(interface_obj->group_obj->p2p_members_list);
  }
  g_mutex_unlock(&interface_obj->group_obj->lock_member_list);

  g_hash_table_unref(interface_obj->group_obj->p2p_members_list);
  g_object_unref(interface_obj->group_obj->proxy);

  g_free(interface_obj->group_obj);
  interface_obj->group_obj = NULL;
}

gint
group_add_group_obj_to_interface(struct wpa_interface_t *interface_obj, gchar *obj_str,
                                 struct group_signals_cb_t *group_signals_cb,
                                 GDestroyNotify key_destroy_func, GDestroyNotify value_destroy_func)
{
  struct group_t *group_obj = NULL;
  g_autoptr(GError) err = NULL;
  GVariant *tmp;

  if (!obj_str || !interface_obj) {
    logg_err("wrong parameter");
    return -1;
  }

  if (interface_obj->group_obj) {
    logg_err("there is still a group active");
    return -1;
  }

  group_obj = calloc(1, sizeof(*group_obj));

  if (!group_obj) {
    logg_err("error calloc group_obj");
    return -1;
  }

  group_obj->proxy = wpa_group__proxy_new_sync(interface_obj->wpa_obj->dbus_connection,
                                               G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME, obj_str, NULL,
                                               &err);

  if (err) {
    logg_err("get p2p_dev wpa_proxy error %s", err->message);
    free(group_obj);
    return -1;
  }

  tmp = wpa_group__get_ssid(group_obj->proxy);

  group_obj->ssid = common_byte_array_to_string(tmp, false);
  group_obj->passphrase = wpa_group__dup_passphrase(group_obj->proxy);
  group_obj->frequency = wpa_group__get_frequency(group_obj->proxy);
  group_obj->obj_str = g_strdup(obj_str);
  group_obj->interface = interface_obj;
  g_mutex_init(&group_obj->lock_member_list);

  p2p_logg_info("SSID %s, passphrase: %s, frequency: %u MHz", group_obj->ssid,
                group_obj->passphrase, group_obj->frequency);

  if (group_signals_cb) {
    group_obj->signals_cb = group_signals_cb;
    group_signals_connect(group_obj);
  }
  group_obj->p2p_members_list = g_hash_table_new_full(g_str_hash, g_str_equal, key_destroy_func,
                                                      value_destroy_func);
  interface_obj->group_obj = group_obj;

  return 0;
}
