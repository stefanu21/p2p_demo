/*
 * Generated by gdbus-codegen 2.48.2. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __WPA_GROUP_H__
#define __WPA_GROUP_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.DBus.Introspectable */

#define WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE (wpa_group_org_freedesktop_dbus_introspectable_get_type ())
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE, wpagroupOrgFreedesktopDBusIntrospectable))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE, wpagroupOrgFreedesktopDBusIntrospectableIface))

struct _wpagroupOrgFreedesktopDBusIntrospectable;
typedef struct _wpagroupOrgFreedesktopDBusIntrospectable wpagroupOrgFreedesktopDBusIntrospectable;
typedef struct _wpagroupOrgFreedesktopDBusIntrospectableIface wpagroupOrgFreedesktopDBusIntrospectableIface;

struct _wpagroupOrgFreedesktopDBusIntrospectableIface
{
  GTypeInterface parent_iface;

  gboolean (*handle_introspect) (
    wpagroupOrgFreedesktopDBusIntrospectable *object,
    GDBusMethodInvocation *invocation);

};

GType wpa_group_org_freedesktop_dbus_introspectable_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *wpa_group_org_freedesktop_dbus_introspectable_interface_info (void);
guint wpa_group_org_freedesktop_dbus_introspectable_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void wpa_group_org_freedesktop_dbus_introspectable_complete_introspect (
    wpagroupOrgFreedesktopDBusIntrospectable *object,
    GDBusMethodInvocation *invocation,
    const gchar *data);



/* D-Bus method calls: */
void wpa_group_org_freedesktop_dbus_introspectable_call_introspect (
    wpagroupOrgFreedesktopDBusIntrospectable *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean wpa_group_org_freedesktop_dbus_introspectable_call_introspect_finish (
    wpagroupOrgFreedesktopDBusIntrospectable *proxy,
    gchar **out_data,
    GAsyncResult *res,
    GError **error);

gboolean wpa_group_org_freedesktop_dbus_introspectable_call_introspect_sync (
    wpagroupOrgFreedesktopDBusIntrospectable *proxy,
    gchar **out_data,
    GCancellable *cancellable,
    GError **error);



/* ---- */

#define WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY (wpa_group_org_freedesktop_dbus_introspectable_proxy_get_type ())
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY, wpagroupOrgFreedesktopDBusIntrospectableProxy))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY, wpagroupOrgFreedesktopDBusIntrospectableProxyClass))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY, wpagroupOrgFreedesktopDBusIntrospectableProxyClass))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY))

typedef struct _wpagroupOrgFreedesktopDBusIntrospectableProxy wpagroupOrgFreedesktopDBusIntrospectableProxy;
typedef struct _wpagroupOrgFreedesktopDBusIntrospectableProxyClass wpagroupOrgFreedesktopDBusIntrospectableProxyClass;
typedef struct _wpagroupOrgFreedesktopDBusIntrospectableProxyPrivate wpagroupOrgFreedesktopDBusIntrospectableProxyPrivate;

struct _wpagroupOrgFreedesktopDBusIntrospectableProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  wpagroupOrgFreedesktopDBusIntrospectableProxyPrivate *priv;
};

struct _wpagroupOrgFreedesktopDBusIntrospectableProxyClass
{
  GDBusProxyClass parent_class;
};

GType wpa_group_org_freedesktop_dbus_introspectable_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpagroupOrgFreedesktopDBusIntrospectableProxy, g_object_unref)
#endif

void wpa_group_org_freedesktop_dbus_introspectable_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpagroupOrgFreedesktopDBusIntrospectable *wpa_group_org_freedesktop_dbus_introspectable_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
wpagroupOrgFreedesktopDBusIntrospectable *wpa_group_org_freedesktop_dbus_introspectable_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void wpa_group_org_freedesktop_dbus_introspectable_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpagroupOrgFreedesktopDBusIntrospectable *wpa_group_org_freedesktop_dbus_introspectable_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
wpagroupOrgFreedesktopDBusIntrospectable *wpa_group_org_freedesktop_dbus_introspectable_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON (wpa_group_org_freedesktop_dbus_introspectable_skeleton_get_type ())
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON, wpagroupOrgFreedesktopDBusIntrospectableSkeleton))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON, wpagroupOrgFreedesktopDBusIntrospectableSkeletonClass))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON, wpagroupOrgFreedesktopDBusIntrospectableSkeletonClass))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON))

typedef struct _wpagroupOrgFreedesktopDBusIntrospectableSkeleton wpagroupOrgFreedesktopDBusIntrospectableSkeleton;
typedef struct _wpagroupOrgFreedesktopDBusIntrospectableSkeletonClass wpagroupOrgFreedesktopDBusIntrospectableSkeletonClass;
typedef struct _wpagroupOrgFreedesktopDBusIntrospectableSkeletonPrivate wpagroupOrgFreedesktopDBusIntrospectableSkeletonPrivate;

struct _wpagroupOrgFreedesktopDBusIntrospectableSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  wpagroupOrgFreedesktopDBusIntrospectableSkeletonPrivate *priv;
};

struct _wpagroupOrgFreedesktopDBusIntrospectableSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType wpa_group_org_freedesktop_dbus_introspectable_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpagroupOrgFreedesktopDBusIntrospectableSkeleton, g_object_unref)
#endif

wpagroupOrgFreedesktopDBusIntrospectable *wpa_group_org_freedesktop_dbus_introspectable_skeleton_new (void);


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.DBus.Properties */

#define WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES (wpa_group_org_freedesktop_dbus_properties_get_type ())
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES, wpagroupOrgFreedesktopDBusProperties))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES, wpagroupOrgFreedesktopDBusPropertiesIface))

struct _wpagroupOrgFreedesktopDBusProperties;
typedef struct _wpagroupOrgFreedesktopDBusProperties wpagroupOrgFreedesktopDBusProperties;
typedef struct _wpagroupOrgFreedesktopDBusPropertiesIface wpagroupOrgFreedesktopDBusPropertiesIface;

struct _wpagroupOrgFreedesktopDBusPropertiesIface
{
  GTypeInterface parent_iface;

  gboolean (*handle_get) (
    wpagroupOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_interface,
    const gchar *arg_propname);

  gboolean (*handle_get_all) (
    wpagroupOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_interface);

  gboolean (*handle_set) (
    wpagroupOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GVariant *arg_value);

};

GType wpa_group_org_freedesktop_dbus_properties_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *wpa_group_org_freedesktop_dbus_properties_interface_info (void);
guint wpa_group_org_freedesktop_dbus_properties_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void wpa_group_org_freedesktop_dbus_properties_complete_get (
    wpagroupOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    GVariant *value);

void wpa_group_org_freedesktop_dbus_properties_complete_get_all (
    wpagroupOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation,
    GVariant *props);

void wpa_group_org_freedesktop_dbus_properties_complete_set (
    wpagroupOrgFreedesktopDBusProperties *object,
    GDBusMethodInvocation *invocation);



/* D-Bus method calls: */
void wpa_group_org_freedesktop_dbus_properties_call_get (
    wpagroupOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean wpa_group_org_freedesktop_dbus_properties_call_get_finish (
    wpagroupOrgFreedesktopDBusProperties *proxy,
    GVariant **out_value,
    GAsyncResult *res,
    GError **error);

gboolean wpa_group_org_freedesktop_dbus_properties_call_get_sync (
    wpagroupOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GVariant **out_value,
    GCancellable *cancellable,
    GError **error);

void wpa_group_org_freedesktop_dbus_properties_call_get_all (
    wpagroupOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean wpa_group_org_freedesktop_dbus_properties_call_get_all_finish (
    wpagroupOrgFreedesktopDBusProperties *proxy,
    GVariant **out_props,
    GAsyncResult *res,
    GError **error);

gboolean wpa_group_org_freedesktop_dbus_properties_call_get_all_sync (
    wpagroupOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    GVariant **out_props,
    GCancellable *cancellable,
    GError **error);

void wpa_group_org_freedesktop_dbus_properties_call_set (
    wpagroupOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GVariant *arg_value,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean wpa_group_org_freedesktop_dbus_properties_call_set_finish (
    wpagroupOrgFreedesktopDBusProperties *proxy,
    GAsyncResult *res,
    GError **error);

gboolean wpa_group_org_freedesktop_dbus_properties_call_set_sync (
    wpagroupOrgFreedesktopDBusProperties *proxy,
    const gchar *arg_interface,
    const gchar *arg_propname,
    GVariant *arg_value,
    GCancellable *cancellable,
    GError **error);



/* ---- */

#define WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY (wpa_group_org_freedesktop_dbus_properties_proxy_get_type ())
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY, wpagroupOrgFreedesktopDBusPropertiesProxy))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY, wpagroupOrgFreedesktopDBusPropertiesProxyClass))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY, wpagroupOrgFreedesktopDBusPropertiesProxyClass))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY))

typedef struct _wpagroupOrgFreedesktopDBusPropertiesProxy wpagroupOrgFreedesktopDBusPropertiesProxy;
typedef struct _wpagroupOrgFreedesktopDBusPropertiesProxyClass wpagroupOrgFreedesktopDBusPropertiesProxyClass;
typedef struct _wpagroupOrgFreedesktopDBusPropertiesProxyPrivate wpagroupOrgFreedesktopDBusPropertiesProxyPrivate;

struct _wpagroupOrgFreedesktopDBusPropertiesProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  wpagroupOrgFreedesktopDBusPropertiesProxyPrivate *priv;
};

struct _wpagroupOrgFreedesktopDBusPropertiesProxyClass
{
  GDBusProxyClass parent_class;
};

GType wpa_group_org_freedesktop_dbus_properties_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpagroupOrgFreedesktopDBusPropertiesProxy, g_object_unref)
#endif

void wpa_group_org_freedesktop_dbus_properties_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpagroupOrgFreedesktopDBusProperties *wpa_group_org_freedesktop_dbus_properties_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
wpagroupOrgFreedesktopDBusProperties *wpa_group_org_freedesktop_dbus_properties_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void wpa_group_org_freedesktop_dbus_properties_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpagroupOrgFreedesktopDBusProperties *wpa_group_org_freedesktop_dbus_properties_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
wpagroupOrgFreedesktopDBusProperties *wpa_group_org_freedesktop_dbus_properties_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON (wpa_group_org_freedesktop_dbus_properties_skeleton_get_type ())
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON, wpagroupOrgFreedesktopDBusPropertiesSkeleton))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON, wpagroupOrgFreedesktopDBusPropertiesSkeletonClass))
#define WPA_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON, wpagroupOrgFreedesktopDBusPropertiesSkeletonClass))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON))
#define WPA_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON))

typedef struct _wpagroupOrgFreedesktopDBusPropertiesSkeleton wpagroupOrgFreedesktopDBusPropertiesSkeleton;
typedef struct _wpagroupOrgFreedesktopDBusPropertiesSkeletonClass wpagroupOrgFreedesktopDBusPropertiesSkeletonClass;
typedef struct _wpagroupOrgFreedesktopDBusPropertiesSkeletonPrivate wpagroupOrgFreedesktopDBusPropertiesSkeletonPrivate;

struct _wpagroupOrgFreedesktopDBusPropertiesSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  wpagroupOrgFreedesktopDBusPropertiesSkeletonPrivate *priv;
};

struct _wpagroupOrgFreedesktopDBusPropertiesSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType wpa_group_org_freedesktop_dbus_properties_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpagroupOrgFreedesktopDBusPropertiesSkeleton, g_object_unref)
#endif

wpagroupOrgFreedesktopDBusProperties *wpa_group_org_freedesktop_dbus_properties_skeleton_new (void);


/* ------------------------------------------------------------------------ */
/* Declarations for fi.w1.wpa_supplicant1.Group */

#define WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP (wpa_group_fi_w1_wpa_supplicant1_group_get_type ())
#define WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP, wpagroupFiW1Wpa_supplicant1Group))
#define WPA_GROUP_IS_FI_W1_WPA_SUPPLICANT1_GROUP(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP))
#define WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP, wpagroupFiW1Wpa_supplicant1GroupIface))

struct _wpagroupFiW1Wpa_supplicant1Group;
typedef struct _wpagroupFiW1Wpa_supplicant1Group wpagroupFiW1Wpa_supplicant1Group;
typedef struct _wpagroupFiW1Wpa_supplicant1GroupIface wpagroupFiW1Wpa_supplicant1GroupIface;

struct _wpagroupFiW1Wpa_supplicant1GroupIface
{
  GTypeInterface parent_iface;


  const gchar * (*get_bssid) (wpagroupFiW1Wpa_supplicant1Group *object);

  guint16  (*get_frequency) (wpagroupFiW1Wpa_supplicant1Group *object);

  const gchar * (*get_group) (wpagroupFiW1Wpa_supplicant1Group *object);

  const gchar *const * (*get_members) (wpagroupFiW1Wpa_supplicant1Group *object);

  const gchar * (*get_passphrase) (wpagroupFiW1Wpa_supplicant1Group *object);

  const gchar * (*get_psk) (wpagroupFiW1Wpa_supplicant1Group *object);

  const gchar * (*get_role) (wpagroupFiW1Wpa_supplicant1Group *object);

  const gchar * (*get_ssid) (wpagroupFiW1Wpa_supplicant1Group *object);

  const gchar *const * (*get_wpsvendor_extensions) (wpagroupFiW1Wpa_supplicant1Group *object);

  void (*peer_disconnected) (
    wpagroupFiW1Wpa_supplicant1Group *object,
    const gchar *arg_peer);

  void (*peer_joined) (
    wpagroupFiW1Wpa_supplicant1Group *object,
    const gchar *arg_peer);

};

GType wpa_group_fi_w1_wpa_supplicant1_group_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *wpa_group_fi_w1_wpa_supplicant1_group_interface_info (void);
guint wpa_group_fi_w1_wpa_supplicant1_group_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus signal emissions functions: */
void wpa_group_fi_w1_wpa_supplicant1_group_emit_peer_joined (
    wpagroupFiW1Wpa_supplicant1Group *object,
    const gchar *arg_peer);

void wpa_group_fi_w1_wpa_supplicant1_group_emit_peer_disconnected (
    wpagroupFiW1Wpa_supplicant1Group *object,
    const gchar *arg_peer);



/* D-Bus property accessors: */
const gchar *const *wpa_group_fi_w1_wpa_supplicant1_group_get_members (wpagroupFiW1Wpa_supplicant1Group *object);
gchar **wpa_group_fi_w1_wpa_supplicant1_group_dup_members (wpagroupFiW1Wpa_supplicant1Group *object);
void wpa_group_fi_w1_wpa_supplicant1_group_set_members (wpagroupFiW1Wpa_supplicant1Group *object, const gchar *const *value);

const gchar *wpa_group_fi_w1_wpa_supplicant1_group_get_group (wpagroupFiW1Wpa_supplicant1Group *object);
gchar *wpa_group_fi_w1_wpa_supplicant1_group_dup_group (wpagroupFiW1Wpa_supplicant1Group *object);
void wpa_group_fi_w1_wpa_supplicant1_group_set_group (wpagroupFiW1Wpa_supplicant1Group *object, const gchar *value);

const gchar *wpa_group_fi_w1_wpa_supplicant1_group_get_role (wpagroupFiW1Wpa_supplicant1Group *object);
gchar *wpa_group_fi_w1_wpa_supplicant1_group_dup_role (wpagroupFiW1Wpa_supplicant1Group *object);
void wpa_group_fi_w1_wpa_supplicant1_group_set_role (wpagroupFiW1Wpa_supplicant1Group *object, const gchar *value);

const gchar *wpa_group_fi_w1_wpa_supplicant1_group_get_ssid (wpagroupFiW1Wpa_supplicant1Group *object);
gchar *wpa_group_fi_w1_wpa_supplicant1_group_dup_ssid (wpagroupFiW1Wpa_supplicant1Group *object);
void wpa_group_fi_w1_wpa_supplicant1_group_set_ssid (wpagroupFiW1Wpa_supplicant1Group *object, const gchar *value);

const gchar *wpa_group_fi_w1_wpa_supplicant1_group_get_bssid (wpagroupFiW1Wpa_supplicant1Group *object);
gchar *wpa_group_fi_w1_wpa_supplicant1_group_dup_bssid (wpagroupFiW1Wpa_supplicant1Group *object);
void wpa_group_fi_w1_wpa_supplicant1_group_set_bssid (wpagroupFiW1Wpa_supplicant1Group *object, const gchar *value);

guint16 wpa_group_fi_w1_wpa_supplicant1_group_get_frequency (wpagroupFiW1Wpa_supplicant1Group *object);
void wpa_group_fi_w1_wpa_supplicant1_group_set_frequency (wpagroupFiW1Wpa_supplicant1Group *object, guint16 value);

const gchar *wpa_group_fi_w1_wpa_supplicant1_group_get_passphrase (wpagroupFiW1Wpa_supplicant1Group *object);
gchar *wpa_group_fi_w1_wpa_supplicant1_group_dup_passphrase (wpagroupFiW1Wpa_supplicant1Group *object);
void wpa_group_fi_w1_wpa_supplicant1_group_set_passphrase (wpagroupFiW1Wpa_supplicant1Group *object, const gchar *value);

const gchar *wpa_group_fi_w1_wpa_supplicant1_group_get_psk (wpagroupFiW1Wpa_supplicant1Group *object);
gchar *wpa_group_fi_w1_wpa_supplicant1_group_dup_psk (wpagroupFiW1Wpa_supplicant1Group *object);
void wpa_group_fi_w1_wpa_supplicant1_group_set_psk (wpagroupFiW1Wpa_supplicant1Group *object, const gchar *value);

const gchar *const *wpa_group_fi_w1_wpa_supplicant1_group_get_wpsvendor_extensions (wpagroupFiW1Wpa_supplicant1Group *object);
gchar **wpa_group_fi_w1_wpa_supplicant1_group_dup_wpsvendor_extensions (wpagroupFiW1Wpa_supplicant1Group *object);
void wpa_group_fi_w1_wpa_supplicant1_group_set_wpsvendor_extensions (wpagroupFiW1Wpa_supplicant1Group *object, const gchar *const *value);


/* ---- */

#define WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY (wpa_group_fi_w1_wpa_supplicant1_group_proxy_get_type ())
#define WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY, wpagroupFiW1Wpa_supplicant1GroupProxy))
#define WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY, wpagroupFiW1Wpa_supplicant1GroupProxyClass))
#define WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY, wpagroupFiW1Wpa_supplicant1GroupProxyClass))
#define WPA_GROUP_IS_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY))
#define WPA_GROUP_IS_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY))

typedef struct _wpagroupFiW1Wpa_supplicant1GroupProxy wpagroupFiW1Wpa_supplicant1GroupProxy;
typedef struct _wpagroupFiW1Wpa_supplicant1GroupProxyClass wpagroupFiW1Wpa_supplicant1GroupProxyClass;
typedef struct _wpagroupFiW1Wpa_supplicant1GroupProxyPrivate wpagroupFiW1Wpa_supplicant1GroupProxyPrivate;

struct _wpagroupFiW1Wpa_supplicant1GroupProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  wpagroupFiW1Wpa_supplicant1GroupProxyPrivate *priv;
};

struct _wpagroupFiW1Wpa_supplicant1GroupProxyClass
{
  GDBusProxyClass parent_class;
};

GType wpa_group_fi_w1_wpa_supplicant1_group_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpagroupFiW1Wpa_supplicant1GroupProxy, g_object_unref)
#endif

void wpa_group_fi_w1_wpa_supplicant1_group_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpagroupFiW1Wpa_supplicant1Group *wpa_group_fi_w1_wpa_supplicant1_group_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
wpagroupFiW1Wpa_supplicant1Group *wpa_group_fi_w1_wpa_supplicant1_group_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void wpa_group_fi_w1_wpa_supplicant1_group_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
wpagroupFiW1Wpa_supplicant1Group *wpa_group_fi_w1_wpa_supplicant1_group_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
wpagroupFiW1Wpa_supplicant1Group *wpa_group_fi_w1_wpa_supplicant1_group_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON (wpa_group_fi_w1_wpa_supplicant1_group_skeleton_get_type ())
#define WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON, wpagroupFiW1Wpa_supplicant1GroupSkeleton))
#define WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON, wpagroupFiW1Wpa_supplicant1GroupSkeletonClass))
#define WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON, wpagroupFiW1Wpa_supplicant1GroupSkeletonClass))
#define WPA_GROUP_IS_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON))
#define WPA_GROUP_IS_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), WPA_GROUP_TYPE_FI_W1_WPA_SUPPLICANT1_GROUP_SKELETON))

typedef struct _wpagroupFiW1Wpa_supplicant1GroupSkeleton wpagroupFiW1Wpa_supplicant1GroupSkeleton;
typedef struct _wpagroupFiW1Wpa_supplicant1GroupSkeletonClass wpagroupFiW1Wpa_supplicant1GroupSkeletonClass;
typedef struct _wpagroupFiW1Wpa_supplicant1GroupSkeletonPrivate wpagroupFiW1Wpa_supplicant1GroupSkeletonPrivate;

struct _wpagroupFiW1Wpa_supplicant1GroupSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  wpagroupFiW1Wpa_supplicant1GroupSkeletonPrivate *priv;
};

struct _wpagroupFiW1Wpa_supplicant1GroupSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType wpa_group_fi_w1_wpa_supplicant1_group_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wpagroupFiW1Wpa_supplicant1GroupSkeleton, g_object_unref)
#endif

wpagroupFiW1Wpa_supplicant1Group *wpa_group_fi_w1_wpa_supplicant1_group_skeleton_new (void);


G_END_DECLS

#endif /* __WPA_GROUP_H__ */
