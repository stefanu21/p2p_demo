#ifndef CBAPP_P2PD_COMMON_H_
#define CBAPP_P2PD_COMMON_H_

#include <gio/gio.h>
#include <glib-object.h>
#include <glib-unix.h>
#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

#include "wpa_code_gen/wpa.h"
#include "wpa_code_gen/wpa_group.h"
#include "wpa_code_gen/wpa_interface.h"
#include "wpa_code_gen/wpa_peer.h"
#include "wpa_code_gen/wpa_pers_group.h"

#define SIGNAL_CONNECT(proxy, signal, name, cb, user_data)                                         \
  do {                                                                                             \
    if (cb) {                                                                                      \
      signal = g_signal_connect(proxy, name, G_CALLBACK(cb), user_data);                           \
    } else                                                                                         \
      signal = 0;                                                                                  \
  } while (0)

#define SIGNAL_DISCONNECT(proxy, signal)                                                           \
  do {                                                                                             \
    if (proxy)                                                                                     \
      g_signal_handler_disconnect(proxy, signal);                                                  \
    signal = 0;                                                                                    \
  } while (0)

#define P2P_VIRTUAL_WLAN_INTERFACE "p2p-wlp0s20-0"
#define P2P_MAIN_WLAN_INTERFACE "wlp0s20f3"

#define WPA_SUP_NAME      "fi.w1.wpa_supplicant1"
#define WPA_SUP_PATH      "/fi/w1/wpa_supplicant1"
#define WPA_SUP_IF_NAME   "fi.w1.wpa_supplicant1"

#define p2p_logg_dbg(FMT, ARGS...)                                                                 \
  do {                                                                                             \
    g_print("%s:%s: " FMT "\n", __FILE__, __FUNCTION__, ##ARGS);                              \
  } while (0)
#define p2p_logg_info(FMT, ARGS...)                                                                \
  do {                                                                                             \
    g_print("%s:%s: " FMT "\n", __FILE__, __FUNCTION__, ##ARGS);                               \
  } while (0)

#define LOCAL_ADDR                      "172.31.254.100"
#define LOCAL_SUBNETMASK                "255.255.255.0"

#define RTSP_TCP_CONTROL_PORT           7236
#define DEV_MAX_AVERABE_THROUGHPUT_MBPS 20

#define EXT_LISTING_PERIOD_MS           500
#define EXT_LISTING_INTERVAL_MS         500
#define GO_INTENT                       15
#define MAX_AUTH_FAIL_COUTNER           3
#define WLAN_SIGNA_QUAL_MAX             70

#define WPA_CONFIG_PATH                 "/tmp/p2p_wpa.conf"

struct miracast_obj_t {
  gchar device_name[64];
  gchar *pin_peer_obj_string;
};

void
common_miracast_obj_destroy(struct miracast_obj_t *obj);
char *
common_byte_array_to_string(GVariant *variant, gboolean as_mac);
#endif /* CBAPP_P2PD_COMMON_H_ */
