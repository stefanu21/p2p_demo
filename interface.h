#ifndef CBAPP_P2PD_INTERFACE_H_
#define CBAPP_P2PD_INTERFACE_H_

#include "common.h"

#include "group.h"
#include "wpa.h"

struct wpa_interface_wps_signals_t {
  gulong prop_changed;
  gulong credentials;
  gulong event;
};

struct wpa_interface_iface_signals_t {
  gulong sta_authorized;
  gulong sta_deauthorized;
  gulong scan_done;
  gulong bss_added;
  gulong bss_removed;
  gulong network_added;
  gulong network_removed;
  gulong network_selected;
  gulong eap;
  gulong network_request;
  gulong properties_changed;
};

struct wpa_interface_wps_signals_cb_t {
  void (*credentials)(WpaInterfaceWPS *object, GVariant *arg_credentials, gpointer user_data);
  void (*event)(WpaInterfaceWPS *object, const gchar *arg_name, GVariant *arg_args,
                gpointer user_data);
  void (*prop_changed)(WpaInterfaceWPS *object, GVariant *arg_properties, gpointer user_data);
};

struct wpa_interface_iface_signals_cb_t {
  void (*properties_changed)(WpaInterface *object, GVariant *arg_properties, gpointer user_data);
  void (*network_request)(WpaInterface *object, const gchar *arg_path, const gchar *arg_field,
                          const gchar *arg_text, gpointer user_data);
  void (*eap)(WpaInterface *object, const gchar *arg_status, const gchar *arg_parameter,
              gpointer user_data);
  void (*network_selected)(WpaInterface *object, const gchar *arg_path, gpointer user_data);
  void (*network_removed)(WpaInterface *object, const gchar *arg_path, gpointer user_data);
  void (*network_added)(WpaInterface *object, const gchar *arg_path, GVariant *arg_properties,
                        gpointer user_data);
  void (*bss_removed)(WpaInterface *object, const gchar *arg_path, gpointer user_data);
  void (*scan_done)(WpaInterface *object, gboolean arg_success, gpointer user_data);
  void (*sta_authorized)(WpaInterface *object, const gchar *arg_name, gpointer user_data);
  void (*bss_added)(WpaInterface *object, const gchar *arg_path, GVariant *arg_properties,
                    gpointer user_data);
  void (*sta_deauthorized)(WpaInterface *object, const gchar *arg_name, gpointer user_data);
};

struct wpa_interface_p2p_signals_t {
  gulong dev_found;
  gulong dev_found_prop;
  gulong dev_lost;
  gulong find_stopped;
  gulong group_started;
  gulong group_formation_failure;
  gulong group_finished;
  gulong gonegotiation_failure;
  gulong gonegotiation_request;
  gulong gonegotiation_success;
  gulong wps_failed;
  gulong service_discovery_request;
  gulong service_discovery_response;
  gulong provision_discovery_response_enter_pin;
  gulong provision_discovery_response_display_pin;
  gulong provision_discovery_request_enter_pin;
  gulong provision_discovery_request_display_pin;
  gulong provision_discovery_pbcresponse;
  gulong provision_discovery_pbcrequest;
  gulong provision_discovery_failure;
  gulong persistent_group_removed;
  gulong persistent_group_added;
  gulong invitation_result;
  gulong invitation_received;
};

struct wpa_interface_p2p_signals_cb_t {
  void (*device_found)(WpaInterfaceP2PDevice *object, const gchar *arg_path, gpointer user_data);
  void (*device_found_properties)(WpaInterfaceP2PDevice *object, const gchar *arg_path,
                                  GVariant *arg_properties, gpointer user_data);
  void (*device_lost)(WpaInterfaceP2PDevice *object, const gchar *arg_path, gpointer user_data);
  void (*find_stopped)(WpaInterfaceP2PDevice *object, gpointer user_data);
  void (*gonegotiation_failure)(WpaInterfaceP2PDevice *object, GVariant *arg_properties,
                                gpointer user_data);
  void (*gonegotiation_request)(WpaInterfaceP2PDevice *object, const gchar *arg_path,
                                guint16 arg_dev_passwd_id, guchar arg_device_go_intent,
                                gpointer user_data);
  void (*gonegotiation_success)(WpaInterfaceP2PDevice *object, GVariant *arg_properties,
                                gpointer user_data);
  void (*group_finished)(WpaInterfaceP2PDevice *object, GVariant *arg_properties,
                         gpointer user_data);
  void (*group_formation_failure)(WpaInterfaceP2PDevice *object, const gchar *arg_reason,
                                  gpointer user_data);
  void (*group_started)(WpaInterfaceP2PDevice *object, GVariant *arg_properties,
                        gpointer user_data);
  void (*invitation_received)(WpaInterfaceP2PDevice *object, GVariant *arg_properties,
                              gpointer user_data);
  void (*invitation_result)(WpaInterfaceP2PDevice *object, GVariant *arg_invite_result,
                            gpointer user_data);
  void (*persistent_group_added)(WpaInterfaceP2PDevice *object, const gchar *arg_path,
                                 GVariant *arg_properties, gpointer user_data);
  void (*persistent_group_removed)(WpaInterfaceP2PDevice *object, const gchar *arg_path,
                                   gpointer user_data);
  void (*provision_discovery_failure)(WpaInterfaceP2PDevice *object, const gchar *arg_peer_object,
                                      gint arg_status, gpointer user_data);
  void (*provision_discovery_pbcrequest)(WpaInterfaceP2PDevice *object,
                                         const gchar *arg_peer_object, gpointer user_data);
  void (*provision_discovery_pbcresponse)(WpaInterfaceP2PDevice *object,
                                          const gchar *arg_peer_object, gpointer user_data);
  void (*provision_discovery_request_display_pin)(WpaInterfaceP2PDevice *object,
                                                  const gchar *arg_peer_object,
                                                  const gchar *arg_pin, gpointer user_data);
  void (*provision_discovery_request_enter_pin)(WpaInterfaceP2PDevice *object,
                                                const gchar *arg_peer_object, gpointer user_data);
  void (*provision_discovery_response_display_pin)(WpaInterfaceP2PDevice *object,
                                                   const gchar *arg_peer_object,
                                                   const gchar *arg_pin, gpointer user_data);
  void (*provision_discovery_response_enter_pin)(WpaInterfaceP2PDevice *object,
                                                 const gchar *arg_peer_object, gpointer user_data);
  void (*service_discovery_request)(WpaInterfaceP2PDevice *object, GVariant *arg_sd_request,
                                    gpointer user_data);
  void (*service_discovery_response)(WpaInterfaceP2PDevice *object, GVariant *arg_sd_response,
                                     gpointer user_data);
  void (*wps_failed)(WpaInterfaceP2PDevice *object, const gchar *arg_name, GVariant *arg_args,
                     gpointer user_data);
};

struct interface_interface_config_t {
  gboolean dhcp_on;
  gchar ip_addr[16];
  gchar ip_mask[16];
  gchar ip_gw[16];
  gchar ip_nameserver[16];
  gchar ip_nameserver2[16];
};

struct wpa_interface_t {
  WpaInterface *iface_proxy;
  WpaInterfaceWPS *iface_wps_proxy;
  WpaInterfaceP2PDevice *iface_p2p_proxy;
  struct interface_interface_config_t interface_config;
  gchar *ifname;
  gchar *obj_str;
  gchar *network_obj_str;
  struct wpa_interface_iface_signals_t iface_signals;
  struct wpa_interface_iface_signals_cb_t *iface_signals_cb;
  struct wpa_interface_p2p_signals_t p2p_signals;
  struct wpa_interface_p2p_signals_cb_t *p2p_signals_cb;
  struct wpa_interface_wps_signals_t wps_signals;
  struct wpa_interface_wps_signals_cb_t *wps_signals_cb;
  struct group_t *group_obj;
  struct wpa_t *wpa_obj;
};

gint
interface_obj_destroy(WpaSupplicant *proxy, struct wpa_interface_t *wpa_interface);
gchar *
interface_create_sync(gchar *ifname, struct wpa_t *obj);
struct wpa_interface_t *
interface_obj_new(gchar *obj_str, struct wpa_interface_iface_signals_cb_t *iface_signals_cb,
                  struct wpa_interface_p2p_signals_cb_t *iface_p2p_signals_cb,
                  struct wpa_interface_wps_signals_cb_t *wps_signals_cb, struct wpa_t *obj);
gint
interface_disconnect_group(struct wpa_t *obj);
gint
interface_connect_group(struct wpa_t *obj, const gchar *ssid, gint frequency_mhz);
gint
interface_remove_interface_by_obj_str(WpaSupplicant *proxy, const gchar *iface_obj_str);
gchar *
interface_get_interface_obj_str_sync(WpaSupplicant *proxy, gchar *ifname);
void
interface_set_extended_listen(WpaInterfaceP2PDevice *proxy, gint period_ms, gint interval_ms);
#endif /* CBAPP_P2PD_INTERFACE_H_ */
