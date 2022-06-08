#ifndef CBAPP_WPA_H_
#define CBAPP_WPA_H_

#include "common.h"

#include "interface.h"

struct wpa_signals_t {
  gulong prop_changed;
  gulong iface_removed;
  gulong iface_added;
};

struct wpa_signals_cb_t {
  void (*prop_changed)(WpaSupplicant *object, GVariant *arg_properties, gpointer user_data);
  void (*iface_removed)(WpaSupplicant *object, const gchar *arg_path, gpointer user_data);
  void (*iface_added)(WpaSupplicant *object, const gchar *arg_path, GVariant *arg_properties,
                      gpointer user_data);
};

struct wpa_t {
  GMainLoop *g_main_loop;
  GDBusConnection *dbus_connection;
  WpaSupplicant *wpa_proxy;
  struct wpa_signals_t wpa_signals;
  struct wpa_signals_cb_t *wpa_signals_cb;
  struct miracast_obj_t miracast;
  struct wpa_interface_t *iface_obj;
  struct wpa_interface_t *ap_iface_obj;
};

void
wpa_signals_disconnect(struct wpa_t *obj);
void
wpa_signals_connect(struct wpa_t *obj);

#endif /* CBAPP_WPA_H_ */
