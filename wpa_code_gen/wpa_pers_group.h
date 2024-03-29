/*
 * This file is generated by gdbus-codegen, do not modify it.
 *
 * The license of this code is the same as for the D-Bus interface description
 * it was derived from. Note that it links to GLib, so must comply with the
 * LGPL linking clauses.
 */

#ifndef __WPA_PERS_GROUP_H__
#define __WPA_PERS_GROUP_H__

#include <gio/gio.h>

G_BEGIN_DECLS

/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.DBus.Introspectable */

#define WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE                              \
  (wpa_persistent_group_org_freedesktop_dbus_introspectable_get_type())
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE(o)                                \
  (G_TYPE_CHECK_INSTANCE_CAST((o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE,  \
                              WpaPersistentGroupOrgFreedesktopDBusIntrospectable))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE(o)                             \
  (G_TYPE_CHECK_INSTANCE_TYPE((o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_GET_IFACE(o)                      \
  (G_TYPE_INSTANCE_GET_INTERFACE((o),                                                              \
                                 WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE,    \
                                 WpaPersistentGroupOrgFreedesktopDBusIntrospectableIface))

struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectable;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectable
  WpaPersistentGroupOrgFreedesktopDBusIntrospectable;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableIface
  WpaPersistentGroupOrgFreedesktopDBusIntrospectableIface;

struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableIface {
  GTypeInterface parent_iface;

  gboolean (*handle_introspect)(WpaPersistentGroupOrgFreedesktopDBusIntrospectable *object,
                                GDBusMethodInvocation *invocation);
};

GType
wpa_persistent_group_org_freedesktop_dbus_introspectable_get_type(void) G_GNUC_CONST;

GDBusInterfaceInfo *
wpa_persistent_group_org_freedesktop_dbus_introspectable_interface_info(void);
guint
wpa_persistent_group_org_freedesktop_dbus_introspectable_override_properties(
  GObjectClass *klass, guint property_id_begin);

/* D-Bus method call completion functions: */
void
wpa_persistent_group_org_freedesktop_dbus_introspectable_complete_introspect(
  WpaPersistentGroupOrgFreedesktopDBusIntrospectable *object, GDBusMethodInvocation *invocation,
  const gchar *data);

/* D-Bus method calls: */
void
wpa_persistent_group_org_freedesktop_dbus_introspectable_call_introspect(
  WpaPersistentGroupOrgFreedesktopDBusIntrospectable *proxy, GCancellable *cancellable,
  GAsyncReadyCallback callback, gpointer user_data);

gboolean
wpa_persistent_group_org_freedesktop_dbus_introspectable_call_introspect_finish(
  WpaPersistentGroupOrgFreedesktopDBusIntrospectable *proxy, gchar **out_data, GAsyncResult *res,
  GError **error);

gboolean
wpa_persistent_group_org_freedesktop_dbus_introspectable_call_introspect_sync(
  WpaPersistentGroupOrgFreedesktopDBusIntrospectable *proxy, gchar **out_data,
  GCancellable *cancellable, GError **error);

/* ---- */

#define WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY                        \
  (wpa_persistent_group_org_freedesktop_dbus_introspectable_proxy_get_type())
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY(o)                          \
  (G_TYPE_CHECK_INSTANCE_CAST((o),                                                                 \
                              WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY, \
                              WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxy))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY_CLASS(k)                    \
  (G_TYPE_CHECK_CLASS_CAST((k),                                                                    \
                           WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY,    \
                           WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxyClass))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY_GET_CLASS(o)                \
  (G_TYPE_INSTANCE_GET_CLASS((o),                                                                  \
                             WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY,  \
                             WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxyClass))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY(o)                       \
  (G_TYPE_CHECK_INSTANCE_TYPE(                                                                     \
    (o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY_CLASS(k)                 \
  (G_TYPE_CHECK_CLASS_TYPE((k),                                                                    \
                           WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_PROXY))

typedef struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxy
  WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxy;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxyClass
  WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxyClass;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxyPrivate
  WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxyPrivate;

struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxy {
  /*< private >*/
  GDBusProxy parent_instance;
  WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxyPrivate *priv;
};

struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxyClass {
  GDBusProxyClass parent_class;
};

GType
wpa_persistent_group_org_freedesktop_dbus_introspectable_proxy_get_type(void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(WpaPersistentGroupOrgFreedesktopDBusIntrospectableProxy,
                              g_object_unref)
#endif

void
wpa_persistent_group_org_freedesktop_dbus_introspectable_proxy_new(
  GDBusConnection *connection, GDBusProxyFlags flags, const gchar *name, const gchar *object_path,
  GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data);
WpaPersistentGroupOrgFreedesktopDBusIntrospectable *
wpa_persistent_group_org_freedesktop_dbus_introspectable_proxy_new_finish(GAsyncResult *res,
                                                                          GError **error);
WpaPersistentGroupOrgFreedesktopDBusIntrospectable *
wpa_persistent_group_org_freedesktop_dbus_introspectable_proxy_new_sync(
  GDBusConnection *connection, GDBusProxyFlags flags, const gchar *name, const gchar *object_path,
  GCancellable *cancellable, GError **error);

void
wpa_persistent_group_org_freedesktop_dbus_introspectable_proxy_new_for_bus(
  GBusType bus_type, GDBusProxyFlags flags, const gchar *name, const gchar *object_path,
  GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data);
WpaPersistentGroupOrgFreedesktopDBusIntrospectable *
wpa_persistent_group_org_freedesktop_dbus_introspectable_proxy_new_for_bus_finish(GAsyncResult *res,
                                                                                  GError **error);
WpaPersistentGroupOrgFreedesktopDBusIntrospectable *
wpa_persistent_group_org_freedesktop_dbus_introspectable_proxy_new_for_bus_sync(
  GBusType bus_type, GDBusProxyFlags flags, const gchar *name, const gchar *object_path,
  GCancellable *cancellable, GError **error);

/* ---- */

#define WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON                     \
  (wpa_persistent_group_org_freedesktop_dbus_introspectable_skeleton_get_type())
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON(o)                       \
  (G_TYPE_CHECK_INSTANCE_CAST(                                                                     \
    (o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON,                   \
    WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeleton))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON_CLASS(k)                 \
  (G_TYPE_CHECK_CLASS_CAST((k),                                                                    \
                           WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON, \
                           WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeletonClass))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON_GET_CLASS(o)             \
  (G_TYPE_INSTANCE_GET_CLASS(                                                                      \
    (o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON,                   \
    WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeletonClass))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON(o)                    \
  (G_TYPE_CHECK_INSTANCE_TYPE(                                                                     \
    (o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON_CLASS(k)              \
  (G_TYPE_CHECK_CLASS_TYPE(                                                                        \
    (k), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_INTROSPECTABLE_SKELETON))

typedef struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeleton
  WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeleton;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeletonClass
  WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeletonClass;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeletonPrivate
  WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeletonPrivate;

struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeleton {
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeletonPrivate *priv;
};

struct _WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeletonClass {
  GDBusInterfaceSkeletonClass parent_class;
};

GType
wpa_persistent_group_org_freedesktop_dbus_introspectable_skeleton_get_type(void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(WpaPersistentGroupOrgFreedesktopDBusIntrospectableSkeleton,
                              g_object_unref)
#endif

WpaPersistentGroupOrgFreedesktopDBusIntrospectable *
wpa_persistent_group_org_freedesktop_dbus_introspectable_skeleton_new(void);

/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.DBus.Properties */

#define WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES                                  \
  (wpa_persistent_group_org_freedesktop_dbus_properties_get_type())
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES(o)                                    \
  (G_TYPE_CHECK_INSTANCE_CAST((o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES,      \
                              WpaPersistentGroupOrgFreedesktopDBusProperties))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES(o)                                 \
  (G_TYPE_CHECK_INSTANCE_TYPE((o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_GET_IFACE(o)                          \
  (G_TYPE_INSTANCE_GET_INTERFACE((o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES,   \
                                 WpaPersistentGroupOrgFreedesktopDBusPropertiesIface))

struct _WpaPersistentGroupOrgFreedesktopDBusProperties;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusProperties
  WpaPersistentGroupOrgFreedesktopDBusProperties;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesIface
  WpaPersistentGroupOrgFreedesktopDBusPropertiesIface;

struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesIface {
  GTypeInterface parent_iface;

  gboolean (*handle_get)(WpaPersistentGroupOrgFreedesktopDBusProperties *object,
                         GDBusMethodInvocation *invocation, const gchar *arg_interface,
                         const gchar *arg_propname);

  gboolean (*handle_get_all)(WpaPersistentGroupOrgFreedesktopDBusProperties *object,
                             GDBusMethodInvocation *invocation, const gchar *arg_interface);

  gboolean (*handle_set)(WpaPersistentGroupOrgFreedesktopDBusProperties *object,
                         GDBusMethodInvocation *invocation, const gchar *arg_interface,
                         const gchar *arg_propname, GVariant *arg_value);
};

GType
wpa_persistent_group_org_freedesktop_dbus_properties_get_type(void) G_GNUC_CONST;

GDBusInterfaceInfo *
wpa_persistent_group_org_freedesktop_dbus_properties_interface_info(void);
guint
wpa_persistent_group_org_freedesktop_dbus_properties_override_properties(GObjectClass *klass,
                                                                         guint property_id_begin);

/* D-Bus method call completion functions: */
void
wpa_persistent_group_org_freedesktop_dbus_properties_complete_get(
  WpaPersistentGroupOrgFreedesktopDBusProperties *object, GDBusMethodInvocation *invocation,
  GVariant *value);

void
wpa_persistent_group_org_freedesktop_dbus_properties_complete_get_all(
  WpaPersistentGroupOrgFreedesktopDBusProperties *object, GDBusMethodInvocation *invocation,
  GVariant *props);

void
wpa_persistent_group_org_freedesktop_dbus_properties_complete_set(
  WpaPersistentGroupOrgFreedesktopDBusProperties *object, GDBusMethodInvocation *invocation);

/* D-Bus method calls: */
void
wpa_persistent_group_org_freedesktop_dbus_properties_call_get(
  WpaPersistentGroupOrgFreedesktopDBusProperties *proxy, const gchar *arg_interface,
  const gchar *arg_propname, GCancellable *cancellable, GAsyncReadyCallback callback,
  gpointer user_data);

gboolean
wpa_persistent_group_org_freedesktop_dbus_properties_call_get_finish(
  WpaPersistentGroupOrgFreedesktopDBusProperties *proxy, GVariant **out_value, GAsyncResult *res,
  GError **error);

gboolean
wpa_persistent_group_org_freedesktop_dbus_properties_call_get_sync(
  WpaPersistentGroupOrgFreedesktopDBusProperties *proxy, const gchar *arg_interface,
  const gchar *arg_propname, GVariant **out_value, GCancellable *cancellable, GError **error);

void
wpa_persistent_group_org_freedesktop_dbus_properties_call_get_all(
  WpaPersistentGroupOrgFreedesktopDBusProperties *proxy, const gchar *arg_interface,
  GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data);

gboolean
wpa_persistent_group_org_freedesktop_dbus_properties_call_get_all_finish(
  WpaPersistentGroupOrgFreedesktopDBusProperties *proxy, GVariant **out_props, GAsyncResult *res,
  GError **error);

gboolean
wpa_persistent_group_org_freedesktop_dbus_properties_call_get_all_sync(
  WpaPersistentGroupOrgFreedesktopDBusProperties *proxy, const gchar *arg_interface,
  GVariant **out_props, GCancellable *cancellable, GError **error);

void
wpa_persistent_group_org_freedesktop_dbus_properties_call_set(
  WpaPersistentGroupOrgFreedesktopDBusProperties *proxy, const gchar *arg_interface,
  const gchar *arg_propname, GVariant *arg_value, GCancellable *cancellable,
  GAsyncReadyCallback callback, gpointer user_data);

gboolean
wpa_persistent_group_org_freedesktop_dbus_properties_call_set_finish(
  WpaPersistentGroupOrgFreedesktopDBusProperties *proxy, GAsyncResult *res, GError **error);

gboolean
wpa_persistent_group_org_freedesktop_dbus_properties_call_set_sync(
  WpaPersistentGroupOrgFreedesktopDBusProperties *proxy, const gchar *arg_interface,
  const gchar *arg_propname, GVariant *arg_value, GCancellable *cancellable, GError **error);

/* ---- */

#define WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY                            \
  (wpa_persistent_group_org_freedesktop_dbus_properties_proxy_get_type())
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY(o)                              \
  (G_TYPE_CHECK_INSTANCE_CAST((o),                                                                 \
                              WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY,     \
                              WpaPersistentGroupOrgFreedesktopDBusPropertiesProxy))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY_CLASS(k)                        \
  (G_TYPE_CHECK_CLASS_CAST((k), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY,   \
                           WpaPersistentGroupOrgFreedesktopDBusPropertiesProxyClass))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY_GET_CLASS(o)                    \
  (G_TYPE_INSTANCE_GET_CLASS((o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY, \
                             WpaPersistentGroupOrgFreedesktopDBusPropertiesProxyClass))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY(o)                           \
  (G_TYPE_CHECK_INSTANCE_TYPE((o), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY_CLASS(k)                     \
  (G_TYPE_CHECK_CLASS_TYPE((k), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_PROXY))

typedef struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesProxy
  WpaPersistentGroupOrgFreedesktopDBusPropertiesProxy;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesProxyClass
  WpaPersistentGroupOrgFreedesktopDBusPropertiesProxyClass;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesProxyPrivate
  WpaPersistentGroupOrgFreedesktopDBusPropertiesProxyPrivate;

struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesProxy {
  /*< private >*/
  GDBusProxy parent_instance;
  WpaPersistentGroupOrgFreedesktopDBusPropertiesProxyPrivate *priv;
};

struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesProxyClass {
  GDBusProxyClass parent_class;
};

GType
wpa_persistent_group_org_freedesktop_dbus_properties_proxy_get_type(void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(WpaPersistentGroupOrgFreedesktopDBusPropertiesProxy, g_object_unref)
#endif

void
wpa_persistent_group_org_freedesktop_dbus_properties_proxy_new(
  GDBusConnection *connection, GDBusProxyFlags flags, const gchar *name, const gchar *object_path,
  GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data);
WpaPersistentGroupOrgFreedesktopDBusProperties *
wpa_persistent_group_org_freedesktop_dbus_properties_proxy_new_finish(GAsyncResult *res,
                                                                      GError **error);
WpaPersistentGroupOrgFreedesktopDBusProperties *
wpa_persistent_group_org_freedesktop_dbus_properties_proxy_new_sync(
  GDBusConnection *connection, GDBusProxyFlags flags, const gchar *name, const gchar *object_path,
  GCancellable *cancellable, GError **error);

void
wpa_persistent_group_org_freedesktop_dbus_properties_proxy_new_for_bus(
  GBusType bus_type, GDBusProxyFlags flags, const gchar *name, const gchar *object_path,
  GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data);
WpaPersistentGroupOrgFreedesktopDBusProperties *
wpa_persistent_group_org_freedesktop_dbus_properties_proxy_new_for_bus_finish(GAsyncResult *res,
                                                                              GError **error);
WpaPersistentGroupOrgFreedesktopDBusProperties *
wpa_persistent_group_org_freedesktop_dbus_properties_proxy_new_for_bus_sync(
  GBusType bus_type, GDBusProxyFlags flags, const gchar *name, const gchar *object_path,
  GCancellable *cancellable, GError **error);

/* ---- */

#define WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON                         \
  (wpa_persistent_group_org_freedesktop_dbus_properties_skeleton_get_type())
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON(o)                           \
  (G_TYPE_CHECK_INSTANCE_CAST((o),                                                                 \
                              WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON,  \
                              WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeleton))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON_CLASS(k)                     \
  (G_TYPE_CHECK_CLASS_CAST((k),                                                                    \
                           WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON,     \
                           WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeletonClass))
#define WPA_PERSISTENT_GROUP_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON_GET_CLASS(o)                 \
  (G_TYPE_INSTANCE_GET_CLASS((o),                                                                  \
                             WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON,   \
                             WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeletonClass))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON(o)                        \
  (G_TYPE_CHECK_INSTANCE_TYPE((o),                                                                 \
                              WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON))
#define WPA_PERSISTENT_GROUP_IS_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON_CLASS(k)                  \
  (G_TYPE_CHECK_CLASS_TYPE((k), WPA_PERSISTENT_GROUP_TYPE_ORG_FREEDESKTOP_DBUS_PROPERTIES_SKELETON))

typedef struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeleton
  WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeleton;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeletonClass
  WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeletonClass;
typedef struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeletonPrivate
  WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeletonPrivate;

struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeleton {
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeletonPrivate *priv;
};

struct _WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeletonClass {
  GDBusInterfaceSkeletonClass parent_class;
};

GType
wpa_persistent_group_org_freedesktop_dbus_properties_skeleton_get_type(void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(WpaPersistentGroupOrgFreedesktopDBusPropertiesSkeleton,
                              g_object_unref)
#endif

WpaPersistentGroupOrgFreedesktopDBusProperties *
wpa_persistent_group_org_freedesktop_dbus_properties_skeleton_new(void);

/* ------------------------------------------------------------------------ */
/* Declarations for fi.w1.wpa_supplicant1.PersistentGroup */

#define WPA_PERSISTENT_GROUP_TYPE_ (wpa_persistent_group__get_type())
#define WPA_PERSISTENT_GROUP_(o)                                                                   \
  (G_TYPE_CHECK_INSTANCE_CAST((o), WPA_PERSISTENT_GROUP_TYPE_, WpaPersistentGroup))
#define WPA_PERSISTENT_GROUP_IS_(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), WPA_PERSISTENT_GROUP_TYPE_))
#define WPA_PERSISTENT_GROUP__GET_IFACE(o)                                                         \
  (G_TYPE_INSTANCE_GET_INTERFACE((o), WPA_PERSISTENT_GROUP_TYPE_, WpaPersistentGroupIface))

struct _WpaPersistentGroup;
typedef struct _WpaPersistentGroup WpaPersistentGroup;
typedef struct _WpaPersistentGroupIface WpaPersistentGroupIface;

struct _WpaPersistentGroupIface {
  GTypeInterface parent_iface;

  const gchar *(*get_bssid)(WpaPersistentGroup *object);

  const gchar *(*get_disabled)(WpaPersistentGroup *object);

  gboolean (*get_enabled)(WpaPersistentGroup *object);

  const gchar *(*get_mode)(WpaPersistentGroup *object);

  GVariant *(*get_properties)(WpaPersistentGroup *object);

  const gchar *(*get_psk)(WpaPersistentGroup *object);

  const gchar *(*get_ssid)(WpaPersistentGroup *object);
};

GType
wpa_persistent_group__get_type(void) G_GNUC_CONST;

GDBusInterfaceInfo *
wpa_persistent_group__interface_info(void);
guint
wpa_persistent_group__override_properties(GObjectClass *klass, guint property_id_begin);

/* D-Bus property accessors: */
const gchar *
wpa_persistent_group__get_bssid(WpaPersistentGroup *object);
gchar *
wpa_persistent_group__dup_bssid(WpaPersistentGroup *object);
void
wpa_persistent_group__set_bssid(WpaPersistentGroup *object, const gchar *value);

const gchar *
wpa_persistent_group__get_ssid(WpaPersistentGroup *object);
gchar *
wpa_persistent_group__dup_ssid(WpaPersistentGroup *object);
void
wpa_persistent_group__set_ssid(WpaPersistentGroup *object, const gchar *value);

const gchar *
wpa_persistent_group__get_psk(WpaPersistentGroup *object);
gchar *
wpa_persistent_group__dup_psk(WpaPersistentGroup *object);
void
wpa_persistent_group__set_psk(WpaPersistentGroup *object, const gchar *value);

const gchar *
wpa_persistent_group__get_disabled(WpaPersistentGroup *object);
gchar *
wpa_persistent_group__dup_disabled(WpaPersistentGroup *object);
void
wpa_persistent_group__set_disabled(WpaPersistentGroup *object, const gchar *value);

const gchar *
wpa_persistent_group__get_mode(WpaPersistentGroup *object);
gchar *
wpa_persistent_group__dup_mode(WpaPersistentGroup *object);
void
wpa_persistent_group__set_mode(WpaPersistentGroup *object, const gchar *value);

gboolean
wpa_persistent_group__get_enabled(WpaPersistentGroup *object);
void
wpa_persistent_group__set_enabled(WpaPersistentGroup *object, gboolean value);

GVariant *
wpa_persistent_group__get_properties(WpaPersistentGroup *object);
GVariant *
wpa_persistent_group__dup_properties(WpaPersistentGroup *object);
void
wpa_persistent_group__set_properties(WpaPersistentGroup *object, GVariant *value);

/* ---- */

#define WPA_PERSISTENT_GROUP_TYPE__PROXY (wpa_persistent_group__proxy_get_type())
#define WPA_PERSISTENT_GROUP__PROXY(o)                                                             \
  (G_TYPE_CHECK_INSTANCE_CAST((o), WPA_PERSISTENT_GROUP_TYPE__PROXY, WpaPersistentGroupProxy))
#define WPA_PERSISTENT_GROUP__PROXY_CLASS(k)                                                       \
  (G_TYPE_CHECK_CLASS_CAST((k), WPA_PERSISTENT_GROUP_TYPE__PROXY, WpaPersistentGroupProxyClass))
#define WPA_PERSISTENT_GROUP__PROXY_GET_CLASS(o)                                                   \
  (G_TYPE_INSTANCE_GET_CLASS((o), WPA_PERSISTENT_GROUP_TYPE__PROXY, WpaPersistentGroupProxyClass))
#define WPA_PERSISTENT_GROUP_IS__PROXY(o)                                                          \
  (G_TYPE_CHECK_INSTANCE_TYPE((o), WPA_PERSISTENT_GROUP_TYPE__PROXY))
#define WPA_PERSISTENT_GROUP_IS__PROXY_CLASS(k)                                                    \
  (G_TYPE_CHECK_CLASS_TYPE((k), WPA_PERSISTENT_GROUP_TYPE__PROXY))

typedef struct _WpaPersistentGroupProxy WpaPersistentGroupProxy;
typedef struct _WpaPersistentGroupProxyClass WpaPersistentGroupProxyClass;
typedef struct _WpaPersistentGroupProxyPrivate WpaPersistentGroupProxyPrivate;

struct _WpaPersistentGroupProxy {
  /*< private >*/
  GDBusProxy parent_instance;
  WpaPersistentGroupProxyPrivate *priv;
};

struct _WpaPersistentGroupProxyClass {
  GDBusProxyClass parent_class;
};

GType
wpa_persistent_group__proxy_get_type(void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(WpaPersistentGroupProxy, g_object_unref)
#endif

void
wpa_persistent_group__proxy_new(GDBusConnection *connection, GDBusProxyFlags flags,
                                const gchar *name, const gchar *object_path,
                                GCancellable *cancellable, GAsyncReadyCallback callback,
                                gpointer user_data);
WpaPersistentGroup *
wpa_persistent_group__proxy_new_finish(GAsyncResult *res, GError **error);
WpaPersistentGroup *
wpa_persistent_group__proxy_new_sync(GDBusConnection *connection, GDBusProxyFlags flags,
                                     const gchar *name, const gchar *object_path,
                                     GCancellable *cancellable, GError **error);

void
wpa_persistent_group__proxy_new_for_bus(GBusType bus_type, GDBusProxyFlags flags, const gchar *name,
                                        const gchar *object_path, GCancellable *cancellable,
                                        GAsyncReadyCallback callback, gpointer user_data);
WpaPersistentGroup *
wpa_persistent_group__proxy_new_for_bus_finish(GAsyncResult *res, GError **error);
WpaPersistentGroup *
wpa_persistent_group__proxy_new_for_bus_sync(GBusType bus_type, GDBusProxyFlags flags,
                                             const gchar *name, const gchar *object_path,
                                             GCancellable *cancellable, GError **error);

/* ---- */

#define WPA_PERSISTENT_GROUP_TYPE__SKELETON (wpa_persistent_group__skeleton_get_type())
#define WPA_PERSISTENT_GROUP__SKELETON(o)                                                          \
  (G_TYPE_CHECK_INSTANCE_CAST((o), WPA_PERSISTENT_GROUP_TYPE__SKELETON, WpaPersistentGroupSkeleton))
#define WPA_PERSISTENT_GROUP__SKELETON_CLASS(k)                                                    \
  (G_TYPE_CHECK_CLASS_CAST((k), WPA_PERSISTENT_GROUP_TYPE__SKELETON,                               \
                           WpaPersistentGroupSkeletonClass))
#define WPA_PERSISTENT_GROUP__SKELETON_GET_CLASS(o)                                                \
  (G_TYPE_INSTANCE_GET_CLASS((o), WPA_PERSISTENT_GROUP_TYPE__SKELETON,                             \
                             WpaPersistentGroupSkeletonClass))
#define WPA_PERSISTENT_GROUP_IS__SKELETON(o)                                                       \
  (G_TYPE_CHECK_INSTANCE_TYPE((o), WPA_PERSISTENT_GROUP_TYPE__SKELETON))
#define WPA_PERSISTENT_GROUP_IS__SKELETON_CLASS(k)                                                 \
  (G_TYPE_CHECK_CLASS_TYPE((k), WPA_PERSISTENT_GROUP_TYPE__SKELETON))

typedef struct _WpaPersistentGroupSkeleton WpaPersistentGroupSkeleton;
typedef struct _WpaPersistentGroupSkeletonClass WpaPersistentGroupSkeletonClass;
typedef struct _WpaPersistentGroupSkeletonPrivate WpaPersistentGroupSkeletonPrivate;

struct _WpaPersistentGroupSkeleton {
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  WpaPersistentGroupSkeletonPrivate *priv;
};

struct _WpaPersistentGroupSkeletonClass {
  GDBusInterfaceSkeletonClass parent_class;
};

GType
wpa_persistent_group__skeleton_get_type(void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(WpaPersistentGroupSkeleton, g_object_unref)
#endif

WpaPersistentGroup *
wpa_persistent_group__skeleton_new(void);

G_END_DECLS

#endif /* __WPA_PERS_GROUP_H__ */
