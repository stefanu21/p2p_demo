#ifndef CBAPP_P2PD_GROUP_H_
#define CBAPP_P2PD_GROUP_H_

#include "common.h"
#include "interface.h"

struct group_signals_t {
  gulong peer_disconnected;
  gulong peer_joined;
};

struct group_signals_cb_t {
  void (*peer_joined)(WpaGroup *object, const gchar *arg_peer, gpointer user_data);
  void (*peer_disconnected)(WpaGroup *object, const gchar *arg_peer, gpointer user_data);
};

struct group_t {
  WpaGroup *proxy;
  gchar *obj_str;
  gchar *ssid;
  gchar *passphrase;
  guint16 frequency;
  struct group_signals_t signals;
  struct group_signals_cb_t *signals_cb;
  GMutex lock_member_list;
  GHashTable *p2p_members_list;
  gchar *joining_peer_obj_str;
  struct wpa_interface_t *interface;
};

gint
group_add_group_obj_to_interface(struct wpa_interface_t *interface_obj, gchar *obj_str,
                                 struct group_signals_cb_t *group_signals_cb,
                                 GDestroyNotify key_destroy_func,
                                 GDestroyNotify value_destroy_func);
void
group_remove_group_obj_from_interface(struct wpa_interface_t *interface_obj);
#endif /* CBAPP_P2PD_GROUP_H_ */
