/*
 * Generated by gdbus-codegen 2.48.2. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __WPA_PEER_H__
#define __WPA_PEER_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.DBus.Introspectable */

#define WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE (wpa_peer_org_freedesktop_dbus_introspectable_get_type ())
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE, wpapeerOrgFreedesktopDBusIntrospectable))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE, wpapeerOrgFreedesktopDBusIntrospectableIface))

struct _wpapeerOrgFreedesktopDBusIntrospectable;
typedef struct _wpapeerOrgFreedesktopDBusIntrospectable wpapeerOrgFreedesktopDBusIntrospectable;
typedef struct _wpapeerOrgFreedesktopDBusIntrospectableIface wpapeerOrgFreedesktopDBusIntrospectableIface;

struct _wpapeerOrgFreedesktopDBusIntrospectableIface
{
  GTypeInterface parent_iface;

  gboolean (*handle_introspect) (
    wpapeerOrgFreedesktopDBusIntrospectable *object,
    GDBusMethodInvocation *invocation);

};

GType wpa_peer_org_freedesktop_dbus_introspectable_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *wpa_peer_org_freedesktop_dbus_introspectable_interface_info (void);
guint wpa_peer_org_freedesktop_dbus_introspectable_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void wpa_peer_org_freedesktop_dbus_introspectable_complete_introspect (
    wpapeerOrgFreedesktopDBusIntrospectable *object,
    GDBusMethodInvocation *invocation,
    const gchar *data);



/* D-Bus method calls: */
void wpa_peer_org_freedesktop_dbus_introspectable_call_introspect (
    wpapeerOrgFreedesktopDBusIntrospectable *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean wpa_peer_org_freedesktop_dbus_introspectable_call_introspect_finish (
    wpapeerOrgFreedesktopDBusIntrospectable *proxy,
    gchar **out_data,
    GAsyncResult *res,
    GError **error);

gboolean wpa_peer_org_freedesktop_dbus_introspectable_call_introspect_sync (
    wpapeerOrgFreedesktopDBusIntrospectable *proxy,
    gchar **out_data,
    GCancellable *cancellable,
    GError **error);



/* ---- */

#define WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY (wpa_peer_org_freedesktop_dbus_introspectable_proxy_get_type ())
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY, wpapeerOrgFreedesktopDBusIntrospectableProxy))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY, wpapeerOrgFreedesktopDBusIntrospectableProxyClass))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY, wpapeerOrgFreedesktopDBusIntrospectableProxyClass))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY))

typedef struct _wpapeerOrgFreedesktopDBusIntrospectableProxy wpapeerOrgFreedesktopDBusIntrospectableProxy;
typedef struct _wpapeerOrgFreedesktopDBusIntrospectableProxyClass wpapeerOrgFreedesktopDBusIntrospectableProxyClass;
typedef struct _wpapeerOrgFreedesktopDBusIntrospectableProxyPrivate wpapeerOrgFreedesktopDBusIntrospectableProxyPrivate;

struct _wpapeerOrgFreedesktopDBusIntrospectableProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  wpapeerOrgFreedesktopDBusIntrospectableProxyPrivate *priv;
};

struct _wpapeerOrgFreedesktopDBusIntrospectableProxyClass
{
  GDBusProxyClass parent_class;
};

GType wpa_peer_org_freedesktop_dbus_introspectable_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpapeerOrgFreedesktopDBusIntrospectableProxy, g_object_unref)
#endif

void wpa_peer_org_freedesktop_dbus_introspectable_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpapeerOrgFreedesktopDBusIntrospectable *wpa_peer_org_freedesktop_dbus_introspectable_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
wpapeerOrgFreedesktopDBusIntrospectable *wpa_peer_org_freedesktop_dbus_introspectable_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void wpa_peer_org_freedesktop_dbus_introspectable_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpapeerOrgFreedesktopDBusIntrospectable *wpa_peer_org_freedesktop_dbus_introspectable_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
wpapeerOrgFreedesktopDBusIntrospectable *wpa_peer_org_freedesktop_dbus_introspectable_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON (wpa_peer_org_freedesktop_dbus_introspectable_skeleton_get_type ())
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON, wpapeerOrgFreedesktopDBusIntrospectableSkeleton))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON, wpapeerOrgFreedesktopDBusIntrospectableSkeletonClass))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON, wpapeerOrgFreedesktopDBusIntrospectableSkeletonClass))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON))

typedef struct _wpapeerOrgFreedesktopDBusIntrospectableSkeleton wpapeerOrgFreedesktopDBusIntrospectableSkeleton;
typedef struct _wpapeerOrgFreedesktopDBusIntrospectableSkeletonClass wpapeerOrgFreedesktopDBusIntrospectableSkeletonClass;
typedef struct _wpapeerOrgFreedesktopDBusIntrospectableSkeletonPrivate wpapeerOrgFreedesktopDBusIntrospectableSkeletonPrivate;

struct _wpapeerOrgFreedesktopDBusIntrospectableSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  wpapeerOrgFreedesktopDBusIntrospectableSkeletonPrivate *priv;
};

struct _wpapeerOrgFreedesktopDBusIntrospectableSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType wpa_peer_org_freedesktop_dbus_introspectable_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpapeerOrgFreedesktopDBusIntrospectableSkeleton, g_object_unref)
#endif

wpapeerOrgFreedesktopDBusIntrospectable *wpa_peer_org_freedesktop_dbus_introspectable_skeleton_new (void);


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.DBus.Properties */

#define WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES (wpa_peer_org_freedesktop_dbus_properties_get_type ())
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_PROPERTIES(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES, wpapeerOrgFreedesktopDBusProperties))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_PROPERTIES_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES, wpapeerOrgFreedesktopDBusPropertiesIface))

struct _wpapeerOrgFreedesktopDBusProperties;
typedef struct _wpapeerOrgFreedesktopDBusProperties wpapeerOrgFreedesktopDBusProperties;
typedef struct _wpapeerOrgFreedesktopDBusPropertiesIface wpapeerOrgFreedesktopDBusPropertiesIface;

struct _wpapeerOrgFreedesktopDBusPropertiesIface
{
  GTypeInterface parent_iface;

  gboolean (*handle_get) (
    wpapeerOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_interface,
    const gchar *arg_propname);

  gboolean (*handle_get_all) (
    wpapeerOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_interface);

  gboolean (*handle_set) (
    wpapeerOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GVariant *arg_value);

};

GType wpa_peer_org_freedesktop_dbus_properties_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *wpa_peer_org_freedesktop_dbus_properties_interface_info (void);
guint wpa_peer_org_freedesktop_dbus_properties_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void wpa_peer_org_freedesktop_dbus_properties_complete_get (
    wpapeerOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    GVariant *value);

void wpa_peer_org_freedesktop_dbus_properties_complete_get_all (
    wpapeerOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    GVariant *props);

void wpa_peer_org_freedesktop_dbus_properties_complete_set (
    wpapeerOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation);



/* D-Bus method calls: */
void wpa_peer_org_freedesktop_dbus_properties_call_get (
    wpapeerOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean wpa_peer_org_freedesktop_dbus_properties_call_get_finish (
    wpapeerOrgFreedesktopDBusProperties *proxy,
    GVariant **out_value,
    GAsyncResult *res,
    GError **error);

gboolean wpa_peer_org_freedesktop_dbus_properties_call_get_sync (
    wpapeerOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GVariant **out_value,
    GCancellable *cancellable,
    GError **error);

void wpa_peer_org_freedesktop_dbus_properties_call_get_all (
    wpapeerOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean wpa_peer_org_freedesktop_dbus_properties_call_get_all_finish (
    wpapeerOrgFreedesktopDBusProperties *proxy,
    GVariant **out_props,
    GAsyncResult *res,
    GError **error);

gboolean wpa_peer_org_freedesktop_dbus_properties_call_get_all_sync (
    wpapeerOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    GVariant **out_props,
    GCancellable *cancellable,
    GError **error);

void wpa_peer_org_freedesktop_dbus_properties_call_set (
    wpapeerOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GVariant *arg_value,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean wpa_peer_org_freedesktop_dbus_properties_call_set_finish (
    wpapeerOrgFreedesktopDBusProperties *proxy,
    GAsyncResult *res,
    GError **error);

gboolean wpa_peer_org_freedesktop_dbus_properties_call_set_sync (
    wpapeerOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GVariant *arg_value,
    GCancellable *cancellable,
    GError **error);



/* ---- */

#define WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY (wpa_peer_org_freedesktop_dbus_properties_proxy_get_type ())
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY, wpapeerOrgFreedesktopDBusPropertiesProxy))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY, wpapeerOrgFreedesktopDBusPropertiesProxyClass))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY, wpapeerOrgFreedesktopDBusPropertiesProxyClass))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY))

typedef struct _wpapeerOrgFreedesktopDBusPropertiesProxy wpapeerOrgFreedesktopDBusPropertiesProxy;
typedef struct _wpapeerOrgFreedesktopDBusPropertiesProxyClass wpapeerOrgFreedesktopDBusPropertiesProxyClass;
typedef struct _wpapeerOrgFreedesktopDBusPropertiesProxyPrivate wpapeerOrgFreedesktopDBusPropertiesProxyPrivate;

struct _wpapeerOrgFreedesktopDBusPropertiesProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  wpapeerOrgFreedesktopDBusPropertiesProxyPrivate *priv;
};

struct _wpapeerOrgFreedesktopDBusPropertiesProxyClass
{
  GDBusProxyClass parent_class;
};

GType wpa_peer_org_freedesktop_dbus_properties_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpapeerOrgFreedesktopDBusPropertiesProxy, g_object_unref)
#endif

void wpa_peer_org_freedesktop_dbus_properties_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpapeerOrgFreedesktopDBusProperties *wpa_peer_org_freedesktop_dbus_properties_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
wpapeerOrgFreedesktopDBusProperties *wpa_peer_org_freedesktop_dbus_properties_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void wpa_peer_org_freedesktop_dbus_properties_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpapeerOrgFreedesktopDBusProperties *wpa_peer_org_freedesktop_dbus_properties_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
wpapeerOrgFreedesktopDBusProperties *wpa_peer_org_freedesktop_dbus_properties_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON (wpa_peer_org_freedesktop_dbus_properties_skeleton_get_type ())
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON, wpapeerOrgFreedesktopDBusPropertiesSkeleton))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON, wpapeerOrgFreedesktopDBusPropertiesSkeletonClass))
#define WPA_PEER_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON, wpapeerOrgFreedesktopDBusPropertiesSkeletonClass))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON))
#define WPA_PEER_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_PEER_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON))

typedef struct _wpapeerOrgFreedesktopDBusPropertiesSkeleton wpapeerOrgFreedesktopDBusPropertiesSkeleton;
typedef struct _wpapeerOrgFreedesktopDBusPropertiesSkeletonClass wpapeerOrgFreedesktopDBusPropertiesSkeletonClass;
typedef struct _wpapeerOrgFreedesktopDBusPropertiesSkeletonPrivate wpapeerOrgFreedesktopDBusPropertiesSkeletonPrivate;

struct _wpapeerOrgFreedesktopDBusPropertiesSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  wpapeerOrgFreedesktopDBusPropertiesSkeletonPrivate *priv;
};

struct _wpapeerOrgFreedesktopDBusPropertiesSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType wpa_peer_org_freedesktop_dbus_properties_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpapeerOrgFreedesktopDBusPropertiesSkeleton, g_object_unref)
#endif

wpapeerOrgFreedesktopDBusProperties *wpa_peer_org_freedesktop_dbus_properties_skeleton_new (void);


/* ------------------------------------------------------------------------ */
/* Declarations for fi.w1.wpa_supplicant1.Peer */

#define WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER (wpa_peer_fi_w1_wpa_supplicant1_peer_get_type ())
#define WPA_PEER_FI_W1_WPA_SUPPLICANT1_PEER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER, wpapeerFiW1Wpa_supplicant1Peer))
#define WPA_PEER_IS_FI_W1_WPA_SUPPLICANT1_PEER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER))
#define WPA_PEER_FI_W1_WPA_SUPPLICANT1_PEER_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER, wpapeerFiW1Wpa_supplicant1PeerIface))

struct _wpapeerFiW1Wpa_supplicant1Peer;
typedef struct _wpapeerFiW1Wpa_supplicant1Peer wpapeerFiW1Wpa_supplicant1Peer;
typedef struct _wpapeerFiW1Wpa_supplicant1PeerIface wpapeerFiW1Wpa_supplicant1PeerIface;

struct _wpapeerFiW1Wpa_supplicant1PeerIface
{
  GTypeInterface parent_iface;


  guint16  (*get_config_method) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar * (*get_device_address) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar * (*get_device_name) (wpapeerFiW1Wpa_supplicant1Peer *object);

  guchar  (*get_devicecapability) (wpapeerFiW1Wpa_supplicant1Peer *object);

  guchar  (*get_groupcapability) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar *const * (*get_groups) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar * (*get_ies) (wpapeerFiW1Wpa_supplicant1Peer *object);

  gint  (*get_level) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar * (*get_manufacturer) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar * (*get_model_name) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar * (*get_model_number) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar * (*get_primary_device_type) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar *const * (*get_secondary_device_types) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar * (*get_serial_number) (wpapeerFiW1Wpa_supplicant1Peer *object);

  const gchar *const * (*get_vendor_extension) (wpapeerFiW1Wpa_supplicant1Peer *object);

  void (*properties_changed) (
    wpapeerFiW1Wpa_supplicant1Peer *object,
    GVariant *arg_properties);

};

GType wpa_peer_fi_w1_wpa_supplicant1_peer_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *wpa_peer_fi_w1_wpa_supplicant1_peer_interface_info (void);
guint wpa_peer_fi_w1_wpa_supplicant1_peer_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus signal emissions functions: */
void wpa_peer_fi_w1_wpa_supplicant1_peer_emit_properties_changed (
    wpapeerFiW1Wpa_supplicant1Peer *object,
    GVariant *arg_properties);



/* D-Bus property accessors: */
const gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_get_device_name (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_dup_device_name (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_device_name (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *value);

const gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_get_manufacturer (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_dup_manufacturer (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_manufacturer (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *value);

const gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_get_model_name (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_dup_model_name (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_model_name (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *value);

const gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_get_model_number (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_dup_model_number (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_model_number (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *value);

const gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_get_serial_number (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_dup_serial_number (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_serial_number (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *value);

const gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_get_primary_device_type (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_dup_primary_device_type (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_primary_device_type (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *value);

guint16 wpa_peer_fi_w1_wpa_supplicant1_peer_get_config_method (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_config_method (wpapeerFiW1Wpa_supplicant1Peer *object, guint16 value);

gint wpa_peer_fi_w1_wpa_supplicant1_peer_get_level (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_level (wpapeerFiW1Wpa_supplicant1Peer *object, gint value);

guchar wpa_peer_fi_w1_wpa_supplicant1_peer_get_devicecapability (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_devicecapability (wpapeerFiW1Wpa_supplicant1Peer *object, guchar value);

guchar wpa_peer_fi_w1_wpa_supplicant1_peer_get_groupcapability (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_groupcapability (wpapeerFiW1Wpa_supplicant1Peer *object, guchar value);

const gchar *const *wpa_peer_fi_w1_wpa_supplicant1_peer_get_secondary_device_types (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar **wpa_peer_fi_w1_wpa_supplicant1_peer_dup_secondary_device_types (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_secondary_device_types (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *const *value);

const gchar *const *wpa_peer_fi_w1_wpa_supplicant1_peer_get_vendor_extension (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar **wpa_peer_fi_w1_wpa_supplicant1_peer_dup_vendor_extension (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_vendor_extension (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *const *value);

const gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_get_ies (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_dup_ies (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_ies (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *value);

const gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_get_device_address (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar *wpa_peer_fi_w1_wpa_supplicant1_peer_dup_device_address (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_device_address (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *value);

const gchar *const *wpa_peer_fi_w1_wpa_supplicant1_peer_get_groups (wpapeerFiW1Wpa_supplicant1Peer *object);
gchar **wpa_peer_fi_w1_wpa_supplicant1_peer_dup_groups (wpapeerFiW1Wpa_supplicant1Peer *object);
void wpa_peer_fi_w1_wpa_supplicant1_peer_set_groups (wpapeerFiW1Wpa_supplicant1Peer *object, const gchar *const *value);


/* ---- */

#define WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_PROXY (wpa_peer_fi_w1_wpa_supplicant1_peer_proxy_get_type ())
#define WPA_PEER_FI_W1_WPA_SUPPLICANT1_PEER_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_PROXY, wpapeerFiW1Wpa_supplicant1PeerProxy))
#define WPA_PEER_FI_W1_WPA_SUPPLICANT1_PEER_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_PROXY, wpapeerFiW1Wpa_supplicant1PeerProxyClass))
#define WPA_PEER_FI_W1_WPA_SUPPLICANT1_PEER_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_PROXY, wpapeerFiW1Wpa_supplicant1PeerProxyClass))
#define WPA_PEER_IS_FI_W1_WPA_SUPPLICANT1_PEER_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_PROXY))
#define WPA_PEER_IS_FI_W1_WPA_SUPPLICANT1_PEER_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_PROXY))

typedef struct _wpapeerFiW1Wpa_supplicant1PeerProxy wpapeerFiW1Wpa_supplicant1PeerProxy;
typedef struct _wpapeerFiW1Wpa_supplicant1PeerProxyClass wpapeerFiW1Wpa_supplicant1PeerProxyClass;
typedef struct _wpapeerFiW1Wpa_supplicant1PeerProxyPrivate wpapeerFiW1Wpa_supplicant1PeerProxyPrivate;

struct _wpapeerFiW1Wpa_supplicant1PeerProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  wpapeerFiW1Wpa_supplicant1PeerProxyPrivate *priv;
};

struct _wpapeerFiW1Wpa_supplicant1PeerProxyClass
{
  GDBusProxyClass parent_class;
};

GType wpa_peer_fi_w1_wpa_supplicant1_peer_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpapeerFiW1Wpa_supplicant1PeerProxy, g_object_unref)
#endif

void wpa_peer_fi_w1_wpa_supplicant1_peer_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpapeerFiW1Wpa_supplicant1Peer *wpa_peer_fi_w1_wpa_supplicant1_peer_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
wpapeerFiW1Wpa_supplicant1Peer *wpa_peer_fi_w1_wpa_supplicant1_peer_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void wpa_peer_fi_w1_wpa_supplicant1_peer_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpapeerFiW1Wpa_supplicant1Peer *wpa_peer_fi_w1_wpa_supplicant1_peer_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
wpapeerFiW1Wpa_supplicant1Peer *wpa_peer_fi_w1_wpa_supplicant1_peer_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON (wpa_peer_fi_w1_wpa_supplicant1_peer_skeleton_get_type ())
#define WPA_PEER_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON, wpapeerFiW1Wpa_supplicant1PeerSkeleton))
#define WPA_PEER_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON, wpapeerFiW1Wpa_supplicant1PeerSkeletonClass))
#define WPA_PEER_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON, wpapeerFiW1Wpa_supplicant1PeerSkeletonClass))
#define WPA_PEER_IS_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON))
#define WPA_PEER_IS_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_PEER_TYPE_FI_W1_WPA_SUPPLICANT1_PEER_SKELETON))

typedef struct _wpapeerFiW1Wpa_supplicant1PeerSkeleton wpapeerFiW1Wpa_supplicant1PeerSkeleton;
typedef struct _wpapeerFiW1Wpa_supplicant1PeerSkeletonClass wpapeerFiW1Wpa_supplicant1PeerSkeletonClass;
typedef struct _wpapeerFiW1Wpa_supplicant1PeerSkeletonPrivate wpapeerFiW1Wpa_supplicant1PeerSkeletonPrivate;

struct _wpapeerFiW1Wpa_supplicant1PeerSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  wpapeerFiW1Wpa_supplicant1PeerSkeletonPrivate *priv;
};

struct _wpapeerFiW1Wpa_supplicant1PeerSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType wpa_peer_fi_w1_wpa_supplicant1_peer_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpapeerFiW1Wpa_supplicant1PeerSkeleton, g_object_unref)
#endif

wpapeerFiW1Wpa_supplicant1Peer *wpa_peer_fi_w1_wpa_supplicant1_peer_skeleton_new (void);


G_END_DECLS

#endif /* __WPA_PEER_H__ */
