#include <sys/ioctl.h>

#include "interface.h"
#include "wpa.h"

void
wpa_signals_disconnect(struct wpa_t *obj)
{
  if (!obj->wpa_signals_cb)
    return;

  SIGNAL_DISCONNECT(obj->wpa_proxy, obj->wpa_signals.prop_changed);
  SIGNAL_DISCONNECT(obj->wpa_proxy, obj->wpa_signals.iface_added);
  SIGNAL_DISCONNECT(obj->wpa_proxy, obj->wpa_signals.iface_removed);
}

void
wpa_signals_connect(struct wpa_t *obj)
{
  if (!obj->wpa_signals_cb)
    return;

  SIGNAL_CONNECT(obj->wpa_proxy, obj->wpa_signals.prop_changed, "properties_changed",
                 obj->wpa_signals_cb->prop_changed, obj);
  SIGNAL_CONNECT(obj->wpa_proxy, obj->wpa_signals.iface_removed, "interface_removed",
                 obj->wpa_signals_cb->iface_removed, obj);
  SIGNAL_CONNECT(obj->wpa_proxy, obj->wpa_signals.iface_added, "interface_added",
                 obj->wpa_signals_cb->iface_added, obj);
}
