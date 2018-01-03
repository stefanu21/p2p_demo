#include <stdbool.h>
#include <stdio.h>
#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>

#include "common/log.h"
#include "wpa.h"
#include "wpa_interface.h"
#include "wpa_peer.h"
#include "wpa_group.h"
#include "supplicant.h"

GMainLoop *g_main_loop;

#define WPA_SUP_NAME	"fi.w1.wpa_supplicant1"
#define WPA_SUP_PATH	"/fi/w1/wpa_supplicant1"
#define WPA_SUP_IF_NAME	"fi.w1.wpa_supplicant1"

#define GO_INTENT  15

#define LOCAL_ADDR				"172.31.254.100"
#define LOCAL_SUBNETMASK		"255.255.255.0"
#define RTSP_TCP_CONTROL_PORT	7236
#define DEV_MAX_AVERABE_THROUGHPUT_MBPS		20
#define DEVICE_NAME "Stefan-Test"

gchar *global_group_obj_string = NULL;

#define P2P_INTERFACE_NAME		"wlp3s0"

struct wpa_signals
{
	gulong prop_changed;
	gulong iface_removed;
	gulong iface_added;
};

struct wps_signals
{
	gulong prop_changed;
	gulong credentials;
	gulong event;
};

struct p2p_signals
{
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
	gulong service_discovery_response;
};

struct group_signals
{
	gulong peer_disconnected;
	gulong peer_joined;
};

struct group_obj
{
	wpagroupFiW1Wpa_supplicant1Group *proxy;
	gchar *interface_obj_string;
	gchar *role;
	struct group_signals group_signals;
	GHashTable *peers;
};

struct interface_obj
{
	wpainterfaceP2PDevice *proxy;
	gchar *name;
};

struct wpa_obj
{
	GDBusConnection *dbus_connection;
	gchar *interface_obj_main_string; //main interface
	wpaFiW1Wpa_supplicant1 *proxy_main_wpa;
	wpainterfaceP2PDevice *proxy_main_p2p;
	struct p2p_signals p2p_main_signals;
	wpainterfaceWPS *proxy_main_wps;
	struct wpa_signals wpa_main_signals;
	struct wps_signals wps_main_signals;
	GHashTable *hash_group; // key = peer_obj_path; value = interface_obj_path
	GHashTable *hash_interface; // key = interface_obj; value=proxy
};

void free_string(gpointer data)
{
	if (!data)
	{
		logg_err("data empty");
		return;
	}
	logg(LOG_DEBUG, "freeing: %s %p\n", (gchar *) data, data);
	g_free(data);
}

void disconnect_wpa_signals(struct wpa_obj *obj);
void disconnect_p2p_signals(struct wpa_obj *obj);
void disconnect_wps_signals(struct wpa_obj *obj);

//void destroy_p2p_interface(struct virtual_interface *obj)
//{
//	if (obj)
//	{
//		if (obj->proxy)
//			g_object_unref(obj->proxy);
//
//		g_free(obj->group_obj_string);
//		g_free(obj->role);
//	}
//
//	memset(obj, 0, sizeof(*obj));
//}

void destroy_wpa_obj(struct wpa_obj *obj)
{
	if (obj)
	{
		if (obj->dbus_connection)
			g_object_unref(obj->dbus_connection);
		g_free(obj->interface_obj_main_string);

		if (obj->proxy_main_p2p)
			g_object_unref(obj->proxy_main_p2p);

		if (obj->proxy_main_wpa)
			g_object_unref(obj->proxy_main_wpa);

		if (obj->proxy_main_wps)
			g_object_unref(obj->proxy_main_wps);

		disconnect_p2p_signals(obj);
		disconnect_wpa_signals(obj);
		disconnect_wps_signals(obj);

	}

	memset(obj, 0, sizeof(*obj));
}

static int set_ip_address(const gchar *interface_name, const gchar *ip_addr,
		const gchar *subnetmask)
{
	struct ifreq ifr;
	struct sockaddr_in* addr = (struct sockaddr_in*) &ifr.ifr_addr;
	int rc = -1;

	logg(LOG_DEBUG, "set ip: %s and subnetmask: %s for interface %s",
			ip_addr, subnetmask, interface_name);

	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (fd < 0)
	{
		logg_err("can't open socket");
		return -1;
	}

	g_snprintf(ifr.ifr_name, IFNAMSIZ, "%s", interface_name);

	ifr.ifr_addr.sa_family = AF_INET;
	inet_pton(AF_INET, ip_addr, &addr->sin_addr);
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
	{
		logg_err("error set ip-addr %s", ip_addr);
		goto end;
	}

	inet_pton(AF_INET, subnetmask, &addr->sin_addr);
	if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0)
	{
		logg_err("error set subnetmask %s", subnetmask);
		goto end;
	}

//	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
//	{
//		logg_err("error get if flags");
//		goto end;
//	}
//
//	g_snprintf(ifr.ifr_name, IFNAMSIZ, "%s", interface_name);
//
//	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
//
//	if (ioctl(fd, SIOCSIFFLAGS, &ifr < 0))
//	{
//		logg_err("error set if flags");
//		goto end;
//	}
	rc = 0;
	end: close(fd);
	return rc;
}

void group_signal_peer_disconnected(wpagroupFiW1Wpa_supplicant1Group *object,
		const gchar *arg_peer, gpointer user_data)
{
	GError *err = NULL;
	struct wpa_obj *obj = (struct wpa_obj *) user_data;
	const gchar *group = g_dbus_proxy_get_object_path(
			(GDBusProxy *) WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY(object));
	struct interface_obj *interface_obj;
	guint nr_peers;

	logg(LOG_DEBUG, "%s from group %s", arg_peer, group);

	struct group_obj *group_obj = g_hash_table_lookup(obj->hash_group, group);

	if (!group_obj)
	{
		logg_err("group not fond in hash");
		return;
	}

	if (g_hash_table_remove(group_obj->peers, arg_peer))
		logg(LOG_DEBUG, "peer %s removed from group peer hash table", arg_peer);

	nr_peers = g_hash_table_size(group_obj->peers);

	if (!nr_peers)
	{
		logg(LOG_DEBUG,
				"no peers are connected - remove group %s from interface %s",
				group, group_obj->interface_obj_string);

		interface_obj = g_hash_table_lookup(obj->hash_interface,
				group_obj->interface_obj_string);

		if (!interface_obj)
		{
			logg_err("unknown interface object");

		}
		if (!wpa_interface_p2_pdevice_call_disconnect_sync(interface_obj->proxy,
				NULL, &err) || err)
		{
			logg_err("error cancel connection for interface %s: %s",
					group_obj->interface_obj_string, err ? err->message : "");
			g_error_free(err);
		}
	}
	else
	{
		logg(LOG_DEBUG, "there are still peers connected to the group %s",
				group);
	}
}

void group_signal_peer_joined(wpagroupFiW1Wpa_supplicant1Group *object,
		const gchar *arg_peer, gpointer user_data)
{
	struct wpa_obj *obj = (struct wpa_obj *) user_data;
	const gchar *group = g_dbus_proxy_get_object_path(
			(GDBusProxy *) WPA_GROUP_FI_W1_WPA_SUPPLICANT1_GROUP_PROXY(object));
	logg(LOG_DEBUG, "%s", arg_peer);

	struct group_obj *group_obj = g_hash_table_lookup(obj->hash_group, group);

	if (!group_obj)
	{
		logg_err("group not fond in hash");
		return;
	}

	if (g_hash_table_add(group_obj->peers, g_strdup(arg_peer)))
	{
		logg(LOG_DEBUG, "add new peer to group peer hash table");
	}
	else
	{
		logg_err("there is still a peer in the list");
	}

}

void connect_group_signals(wpagroupFiW1Wpa_supplicant1Group *proxy,
		struct group_signals *group_signals, gpointer user_data)
{

	logg(LOG_DEBUG, "");

	group_signals->peer_disconnected =
			g_signal_connect (proxy,"peer_disconnected",
					G_CALLBACK (group_signal_peer_disconnected),
					user_data);

	if (!group_signals->peer_disconnected)
		logg_err("error init peer_disconnected signal");

	group_signals->peer_joined = g_signal_connect (proxy,"peer_joined",
			G_CALLBACK (group_signal_peer_joined),
			user_data);

	if (!group_signals->peer_joined)
		logg_err("error init peer_joined signal");

}

void disconnect_group_signals(wpagroupFiW1Wpa_supplicant1Group *proxy,
		struct group_signals *group_signals)
{
	logg(LOG_DEBUG, "");

	if (group_signals->peer_disconnected)
		g_signal_handler_disconnect(proxy, group_signals->peer_disconnected);

	if (group_signals->peer_joined)
		g_signal_handler_disconnect(proxy, group_signals->peer_joined);

	memset(group_signals, 0, sizeof(*group_signals));
}

static int hash_insert_group(struct wpa_obj *obj,
		const gchar *interface_obj_string, const gchar *group_obj_string,
		const gchar *role)
{
	struct group_obj *group_obj = NULL;
	GError *err = NULL;

	if (!obj || !interface_obj_string || !group_obj_string || !role)
	{
		logg_err("wrong parameter");
		return -1;
	}

	group_obj = calloc(1, sizeof(*group_obj));

	if (!group_obj)
	{
		logg_err("error calloc group_obj");
		return -1;
	}

	wpagroupFiW1Wpa_supplicant1Group *proxy_group =
			wpa_group_fi_w1_wpa_supplicant1_group_proxy_new_sync(
					obj->dbus_connection, G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME,
					group_obj_string, NULL, &err);

	if (err)
	{
		logg_err("get p2p_dev wpa_proxy error %s", err->message);
		g_error_free(err);
		return -1;
	}

	connect_group_signals(proxy_group, &group_obj->group_signals, obj);
	group_obj->proxy = proxy_group;
	group_obj->interface_obj_string = g_strdup(interface_obj_string);
	group_obj->role = g_strdup(role);
	group_obj->peers = g_hash_table_new_full(g_str_hash, g_str_equal,
			free_string, NULL);

	return g_hash_table_replace(obj->hash_group, g_strdup(group_obj_string),
			group_obj) == false ? 0 : 1;
}

static int hash_insert_interface(struct wpa_obj *obj,
		const gchar *interface_obj_string, const gchar *interface_name)
{
	GError *err = NULL;
	struct interface_obj *interface_obj;

	if (!obj || !interface_obj_string)
	{
		logg_err("wrong paramert");
		return -1;
	}

	interface_obj = calloc(1, sizeof(*interface_obj));

	if (!interface_obj)
	{
		logg_err("error calloc interface_obj");
		return -1;
	}

	interface_obj->proxy = wpa_interface_p2_pdevice_proxy_new_sync(
			obj->dbus_connection, G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME,
			interface_obj_string, NULL, &err);

	if (err)
	{
		logg_err("error proxy p2p create for %s: %s",
				interface_obj_string, err->message);
		g_error_free(err);
		return -1;
	}

	interface_obj->name = g_strdup(interface_name);

	return g_hash_table_replace(obj->hash_interface,
			g_strdup(interface_obj_string), interface_obj) == false ? 0 : 1;
}

void wpa_signal_iface_added(wpaFiW1Wpa_supplicant1 *object,
		const gchar *arg_path, GVariant *arg_properties, gpointer user_data)
{
	struct wpa_obj *obj = (struct wpa_obj *) user_data;
	GVariantIter iter;
	GVariant *value;
	gchar *key;
	gint rc = 0;

	logg(LOG_DEBUG, "%s", arg_path);

	g_variant_iter_init(&iter, arg_properties);
	while (g_variant_iter_next(&iter, "{sv}", &key, &value))
	{
		if (g_strcmp0(key, "Ifname") == 0)
		{
			GError *err = NULL;

			if (g_strcmp0(P2P_INTERFACE_NAME, g_variant_get_string(value, NULL))
					== 0)
			{
				logg(LOG_DEBUG,
						"this must be the main interface -- skip assign ip");
				goto end;
			}
			logg(LOG_DEBUG, "Interface %s created",
					g_variant_get_string(value, NULL));

			global_group_obj_string = g_strdup(arg_path);

			if ((rc = hash_insert_interface(obj, arg_path,
					g_variant_get_string(value, NULL))) < 0)
			{
				logg_err("error insert interface into hash %s", arg_path);
			}
			else if (rc == 1)
				logg(LOG_DEBUG, "interface added to hash table");

			if (err)
			{
				logg_err("get p2p_dev wpa_proxy error %s", err->message);
				goto end;
			}

			// must free data for ourselves
			end: g_variant_unref(value);
			g_free(key);
			return;
		}
		g_variant_unref(value);
		g_free(key);
	}
}

void wpa_signal_iface_removed(wpaFiW1Wpa_supplicant1 *object,
		const gchar *arg_path, gpointer user_data)
{
	struct wpa_obj *obj = (struct wpa_obj *) user_data;

	logg(LOG_DEBUG, "%s", arg_path);

	g_hash_table_remove(obj->hash_interface, (gconstpointer) arg_path);

	g_free(global_group_obj_string);
	global_group_obj_string = NULL;
//	if(obj->interface_obj_main_string && g_strcmp0(arg_path, obj->interface_obj_main_string) == 0)
//	{
//		logg_err("main interface removed");
//		disconnect_p2p_signals(obj);
//		disconnect_wpa_signals(obj);
//		disconnect_wps_signals(obj);
//		g_free(obj->interface_obj_main_string);
//		obj->interface_obj_main_string = NULL;
//
//
//	}
}

void wpa_signal_prop_changed(wpaFiW1Wpa_supplicant1 *object,
		GVariant *arg_properties, gpointer user_data)
{
	gchar *str = g_variant_print(arg_properties, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void disconnect_wpa_signals(struct wpa_obj *obj)
{
	struct wpa_signals *wpa_signals = &obj->wpa_main_signals;
	wpaFiW1Wpa_supplicant1 *proxy = obj->proxy_main_wpa;

	if (wpa_signals->prop_changed)
		g_signal_handler_disconnect(proxy, wpa_signals->prop_changed);

	if (wpa_signals->iface_added)
		g_signal_handler_disconnect(proxy, wpa_signals->iface_added);

	if (wpa_signals->iface_removed)
		g_signal_handler_disconnect(proxy, wpa_signals->iface_removed);

	memset(wpa_signals, 0, sizeof(*wpa_signals));
}

void connect_wpa_signals(struct wpa_obj *obj)
{
	struct wpa_signals *wpa_signals = &obj->wpa_main_signals;
	wpaFiW1Wpa_supplicant1 *proxy = obj->proxy_main_wpa;

	if (wpa_signals->iface_added || wpa_signals->iface_removed
			|| wpa_signals->prop_changed)
	{
		logg_err("signals still initialized reset it");
		disconnect_wpa_signals(obj);
	}

	wpa_signals->prop_changed = g_signal_connect(proxy, "properties_changed",
			G_CALLBACK (wpa_signal_prop_changed), obj);

	if (!wpa_signals->prop_changed)
		logg_err("error init properties changed signal");

	wpa_signals->iface_removed = g_signal_connect(proxy, "interface_removed",
			G_CALLBACK (wpa_signal_iface_removed), obj);

	if (!wpa_signals->iface_removed)
		logg_err("error init interface removed signal");

	wpa_signals->iface_added = g_signal_connect(proxy, "interface_added",
			G_CALLBACK (wpa_signal_iface_added), obj);

	if (!wpa_signals->iface_added)
		logg_err("error init interface added signal");
}

void wps_signal_credentials(wpainterfaceWPS *object, GVariant *arg_credentials,
		gpointer user_data)
{
	gchar *str = g_variant_print(arg_credentials, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void wps_signal_event(wpainterfaceWPS *object, const gchar *arg_name,
		GVariant *arg_args, gpointer user_data)
{
	logg(LOG_DEBUG, "%s", arg_name);
	gchar *str = g_variant_print(arg_args, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void wps_signal_properties_changed(wpainterfaceWPS *object,
		GVariant *arg_properties, gpointer user_data)
{
	gchar *str = g_variant_print(arg_properties, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void disconnect_wps_signals(struct wpa_obj *obj)
{
	struct wps_signals *wps_signals = &obj->wps_main_signals;
	wpainterfaceWPS *proxy = obj->proxy_main_wps;

	if (wps_signals->prop_changed)
		g_signal_handler_disconnect(proxy, wps_signals->prop_changed);

	if (wps_signals->event)
		g_signal_handler_disconnect(proxy, wps_signals->event);

	if (wps_signals->credentials)
		g_signal_handler_disconnect(proxy, wps_signals->credentials);

	memset(wps_signals, 0, sizeof(*wps_signals));
}

void connect_wps_signals(struct wpa_obj *obj)
{
	struct wps_signals *wps_signals = &obj->wps_main_signals;
	wpainterfaceWPS *proxy = obj->proxy_main_wps;

	if (wps_signals->event || wps_signals->credentials
			|| wps_signals->prop_changed)
	{
		logg_err("signals still initialized reset it");
		disconnect_wps_signals(obj);
	}

	wps_signals->prop_changed = g_signal_connect(proxy, "properties_changed",
			G_CALLBACK (wps_signal_properties_changed), obj);

	if (!wps_signals->prop_changed)
		logg_err("error init properties changed signal");

	wps_signals->event = g_signal_connect(proxy, "event",
			G_CALLBACK (wps_signal_event), obj);

	if (!wps_signals->event)
		logg_err("error init event signal");

	wps_signals->credentials = g_signal_connect(proxy, "credentials",
			G_CALLBACK (wps_signal_credentials), obj);

	if (!wps_signals->credentials)
		logg_err("error init credentials signal");
}

void p2p_signal_device_found(wpainterfaceP2PDevice *object,
		const gchar *arg_path, gpointer user_data)
{
	struct wpa_obj *obj = (struct wpa_obj *) user_data;

	//peer obj_path
	logg(LOG_DEBUG, "interface %s", obj->interface_obj_main_string);
	logg(LOG_DEBUG, "%s", arg_path);

}

void p2p_signal_device_found_properties(wpainterfaceP2PDevice *object,
		const gchar *arg_path, GVariant *arg_properties, gpointer user_data)
{
	logg(LOG_DEBUG, "%s", arg_path);
	gchar *str = g_variant_print(arg_properties, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void p2p_signal_device_lost(wpainterfaceP2PDevice *object,
		const gchar *arg_path, gpointer user_data)
{
	// peer obj path
	logg(LOG_DEBUG, "%s", arg_path);

}

void p2p_signal_find_stopped(wpainterfaceP2PDevice *object, gpointer user_data)
{
	logg(LOG_DEBUG, "");
}

void p2p_signal_gonegotiation_failure(wpainterfaceP2PDevice *object,
		GVariant *arg_properties, gpointer user_data)
{
	gchar *str = g_variant_print(arg_properties, TRUE);
	logg_err("%s", str);
	g_free(str);
}

static void gonegotiation_connect_callback(GObject *source_object,
		GAsyncResult *res, gpointer user_data)
{
	GError *err = NULL;
	gchar *generated_pin = NULL;
	wpainterfaceP2PDevice *proxy = (wpainterfaceP2PDevice *) source_object;

	logg(LOG_DEBUG, "connect callback");

	if (!wpa_interface_p2_pdevice_call_connect_finish(proxy, &generated_pin,
			res, &err))
	{
		logg_err("error call connect finish %s",
				err == NULL ? "" : err->message);
	}
	else
		logg(LOG_DEBUG, "generated pin %s", generated_pin);

	g_free(generated_pin);
}

void p2p_signal_gonegotiation_request(wpainterfaceP2PDevice *object,
		const gchar *arg_path, guint16 arg_dev_passwd_id,
		guchar arg_device_go_intent, gpointer user_data)
{
	GVariant *variant;
	logg(LOG_DEBUG, "%s; pw_id: %d; go_intent:%d",
			arg_path, arg_dev_passwd_id, arg_device_go_intent);

	variant = supplicant_create_connect_variant(arg_path, GO_INTENT, "pbc",
			false);

	wpa_interface_p2_pdevice_call_connect(object, variant, NULL,
			gonegotiation_connect_callback, user_data);
}

void p2p_signal_gonegotiation_success(wpainterfaceP2PDevice *object,
		GVariant *arg_properties, gpointer user_data)
{
	gchar *str = g_variant_print(arg_properties, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void p2p_signal_group_finished(wpainterfaceP2PDevice *object,
		GVariant *arg_properties, gpointer user_data)
{
	struct wpa_obj *obj = (struct wpa_obj *) user_data;
	GVariantIter iter;
	GVariant *value;
	gchar *key;

	logg(LOG_DEBUG, "");
	g_variant_iter_init(&iter, arg_properties);

	while (g_variant_iter_next(&iter, "{sv}", &key, &value))
	{

		if (g_strcmp0(key, "role") == 0)
		{
			if (g_strcmp0(g_variant_get_string(value, NULL), "client") == 0)
				system("/home/stefan/02_dbus/stop_dhclient.sh");
			else
				system("/home/stefan/02_dbus/dhcp-stop.sh");
		}

		if (g_strcmp0(key, "interface_object") == 0)
		{
			struct interface_obj *interface_obj = g_hash_table_lookup(
					obj->hash_interface, g_variant_get_string(value, NULL));

			if (!interface_obj)
			{
				logg_err("unknown interface object");
				g_variant_unref(value);
				g_free(key);
				return;
			}

//			if (!wpa_interface_p2_pdevice_call_disconnect_sync(p2p_proxy, NULL,
//					&err) || err)
//			{
//				logg_err("error cancel connection for interface %s: %s",
//						g_variant_get_string(value, NULL), err ? err->message : "");
//				g_error_free(err);
//			}
		}

		if (g_strcmp0(key, "group_object") == 0)
		{
			g_hash_table_remove(obj->hash_group,
					g_variant_get_string(value, NULL));
		}

		g_variant_unref(value);
		g_free(key);
	}
}

void p2p_signal_group_formation_failure(wpainterfaceP2PDevice *object,
		const gchar *arg_reason, gpointer user_data)
{
	logg_err("%s", arg_reason);
}

void p2p_signal_group_started(wpainterfaceP2PDevice *object,
		GVariant *arg_properties, gpointer user_data)
{
	struct wpa_obj *obj = (struct wpa_obj *) user_data;
	GVariantIter iter;
	GVariant *value = NULL;
	gchar *key = NULL;
	gchar *role = NULL, *interface_obj_string = NULL, *group_obj_string = NULL;
	gchar tmp[256];

	g_variant_iter_init(&iter, arg_properties);

	while (g_variant_iter_next(&iter, "{sv}", &key, &value))
	{
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

	logg(LOG_DEBUG, "iface: %s", interface_obj_string);
	logg(LOG_DEBUG, "group_obj: %s", group_obj_string);
	logg(LOG_DEBUG, "roule %s", role);

	if (hash_insert_group(obj, interface_obj_string, group_obj_string, role)
			== 0)
		logg(LOG_DEBUG, "known interface in hash table");

	struct interface_obj *interface_obj = g_hash_table_lookup(
			obj->hash_interface, interface_obj_string);

	if (!interface_obj)
	{
		logg_err("can't get interface object from hash table");
		goto end;
	}

	if (g_strcmp0(role, "client") == 0)
	{
		// TODO: start dhcp server how to?
		g_snprintf(tmp, sizeof(tmp),
				"/home/stefan/02_dbus/start_dhclient.sh %s",
				interface_obj->name);

	}
	else
	{
		set_ip_address(interface_obj->name, LOCAL_ADDR, LOCAL_SUBNETMASK);
		g_snprintf(tmp, sizeof(tmp), "/home/stefan/02_dbus/dhcp-start.sh %s",
				interface_obj->name);
	}

	logg(LOG_DEBUG, "%s", tmp);
	system(tmp);

	end: g_free(interface_obj_string);
	g_free(role);
	g_free(group_obj_string);
}

void p2p_signal_invitation_received(wpainterfaceP2PDevice *object,
		GVariant *arg_properties, gpointer user_data)
{
	gchar *str = g_variant_print(arg_properties, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void p2p_signal_invitation_result(wpainterfaceP2PDevice *object,
		GVariant *arg_invite_result, gpointer user_data)
{
	gchar *str = g_variant_print(arg_invite_result, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void p2p_signal_persistent_group_added(wpainterfaceP2PDevice *object,
		const gchar *arg_path, GVariant *arg_properties, gpointer user_data)
{
	logg(LOG_DEBUG, "%s", arg_path);
	gchar *str = g_variant_print(arg_properties, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void p2p_signal_persistent_group_removed(wpainterfaceP2PDevice *object,
		const gchar *arg_path, gpointer user_data)
{
	logg(LOG_DEBUG, "%s", arg_path);
}

void p2p_signal_provision_discovery_failure(wpainterfaceP2PDevice *object,
		const gchar *arg_peer_object, gint arg_status, gpointer user_data)
{
	logg_err("%s; Status: %d", arg_peer_object, arg_status);
}

void p2p_signal_provision_discovery_pbcrequest(wpainterfaceP2PDevice *object,
		const gchar *arg_peer_object, gpointer user_data)
{
	logg(LOG_DEBUG, "%s", arg_peer_object);

	struct wpa_obj *obj = (struct wpa_obj *) user_data;

	GVariantBuilder *variant_builder = g_variant_builder_new(
			G_VARIANT_TYPE ("a{sv}"));
	GVariant *variant, *variant_ret;

	GHashTableIter iter;
	const gchar *key;
	const struct group_obj *group_obj;

	GError *err = NULL;

	g_hash_table_iter_init(&iter, obj->hash_group);
	while (g_hash_table_iter_next(&iter, (gpointer *) &key,
			(gpointer *) &group_obj))
	{
		logg(LOG_DEBUG, "key: %s", key);

		wpainterfaceWPS *prox_wps = wpa_interface_wps_proxy_new_sync(
				obj->dbus_connection, G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME,
				group_obj->interface_obj_string, NULL, &err);

		if (err)
		{
			logg_err("get iface wps_proxy error %s", err->message);
			g_error_free(err);
			return;
		}

		g_variant_builder_add(variant_builder, "{sv}", "Role",
				g_variant_new("s", "enrollee"));
		g_variant_builder_add(variant_builder, "{sv}", "Type",
				g_variant_new("s", "pbc"));

		variant = g_variant_builder_end(variant_builder);

		g_variant_builder_unref(variant_builder);

		if (!wpa_interface_wps_call_start_sync(prox_wps, variant, &variant_ret,
				NULL, &err) || err)
		{
			logg_err("error create wps start call: %s",
					err ? err->message : "");
			if (err)
				g_error_free(err);
		}

		g_object_unref(prox_wps);
		gchar *str = g_variant_print(variant_ret, TRUE);
		logg(LOG_DEBUG, "%s", str);
		g_free(str);

		g_variant_unref(variant_ret);

	}
}

void p2p_signal_provision_discovery_pbcresponse(wpainterfaceP2PDevice *object,
		const gchar *arg_peer_object, gpointer user_data)
{
	logg(LOG_DEBUG, "%s", arg_peer_object);
}

void p2p_signal_provision_discovery_request_display_pin(
		wpainterfaceP2PDevice *object, const gchar *arg_peer_object,
		const gchar *arg_pin, gpointer user_data)
{
	logg(LOG_DEBUG, "%s; Pin: %s", arg_peer_object, arg_pin);
}

void p2p_signal_provision_discovery_request_enter_pin(
		wpainterfaceP2PDevice *object, const gchar *arg_peer_object,
		gpointer user_data)
{
	logg(LOG_DEBUG, "%s", arg_peer_object);
}

void p2p_signal_provision_discovery_response_display_pin(
		wpainterfaceP2PDevice *object, const gchar *arg_peer_object,
		const gchar *arg_pin, gpointer user_data)
{
	logg(LOG_DEBUG, "%s; Pin: %s", arg_peer_object, arg_pin);
}

void p2p_signal_provision_discovery_response_enter_pin(
		wpainterfaceP2PDevice *object, const gchar *arg_peer_object,
		gpointer user_data)
{
	logg(LOG_DEBUG, "%s", arg_peer_object);
}

void p2p_signal_service_discovery_request(wpainterfaceP2PDevice *object,
		GVariant *arg_sd_request, gpointer user_data)
{
	gchar *str = g_variant_print(arg_sd_request, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void p2p_signal_service_discovery_response(wpainterfaceP2PDevice *object,
		GVariant *arg_sd_response, gpointer user_data)
{
	gchar *str = g_variant_print(arg_sd_response, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void p2p_signal_wps_failed(wpainterfaceP2PDevice *object, const gchar *arg_name,
		GVariant *arg_args, gpointer user_data)
{
	logg_err( "%s", arg_name);
	gchar *str = g_variant_print(arg_args, TRUE);
	logg(LOG_DEBUG, "%s", str);
	g_free(str);
}

void disconnect_p2p_signals(struct wpa_obj *obj)
{
	struct p2p_signals *p2p_signals = &obj->p2p_main_signals;
	wpainterfaceP2PDevice *proxy = obj->proxy_main_p2p;

	if (p2p_signals->dev_found)
		g_signal_handler_disconnect(proxy, p2p_signals->dev_found);

	if (p2p_signals->dev_found_prop)
		g_signal_handler_disconnect(proxy, p2p_signals->dev_found_prop);

	if (p2p_signals->dev_lost)
		g_signal_handler_disconnect(proxy, p2p_signals->dev_lost);

	if (p2p_signals->find_stopped)
		g_signal_handler_disconnect(proxy, p2p_signals->find_stopped);

	if (p2p_signals->group_started)
		g_signal_handler_disconnect(proxy, p2p_signals->group_started);

	if (p2p_signals->group_formation_failure)
		g_signal_handler_disconnect(proxy,
				p2p_signals->group_formation_failure);

	if (p2p_signals->group_finished)
		g_signal_handler_disconnect(proxy, p2p_signals->group_finished);

	if (p2p_signals->gonegotiation_failure)
		g_signal_handler_disconnect(proxy, p2p_signals->gonegotiation_failure);

	if (p2p_signals->gonegotiation_request)
		g_signal_handler_disconnect(proxy, p2p_signals->gonegotiation_request);

	if (p2p_signals->gonegotiation_success)
		g_signal_handler_disconnect(proxy, p2p_signals->gonegotiation_success);

	if (p2p_signals->wps_failed)
		g_signal_handler_disconnect(proxy, p2p_signals->wps_failed);

	if (p2p_signals->service_discovery_request)
		g_signal_handler_disconnect(proxy,
				p2p_signals->service_discovery_request);

	if (p2p_signals->provision_discovery_response_enter_pin)
		g_signal_handler_disconnect(proxy,
				p2p_signals->provision_discovery_response_enter_pin);

	if (p2p_signals->provision_discovery_response_display_pin)
		g_signal_handler_disconnect(proxy,
				p2p_signals->provision_discovery_response_display_pin);

	if (p2p_signals->provision_discovery_request_enter_pin)
		g_signal_handler_disconnect(proxy,
				p2p_signals->provision_discovery_request_enter_pin);

	if (p2p_signals->provision_discovery_request_display_pin)
		g_signal_handler_disconnect(proxy,
				p2p_signals->provision_discovery_request_display_pin);

	if (p2p_signals->provision_discovery_pbcresponse)
		g_signal_handler_disconnect(proxy,
				p2p_signals->provision_discovery_pbcresponse);

	if (p2p_signals->provision_discovery_pbcrequest)
		g_signal_handler_disconnect(proxy,
				p2p_signals->provision_discovery_pbcrequest);

	if (p2p_signals->provision_discovery_failure)
		g_signal_handler_disconnect(proxy,
				p2p_signals->provision_discovery_failure);

	if (p2p_signals->persistent_group_removed)
		g_signal_handler_disconnect(proxy,
				p2p_signals->persistent_group_removed);

	if (p2p_signals->persistent_group_added)
		g_signal_handler_disconnect(proxy, p2p_signals->persistent_group_added);

	if (p2p_signals->invitation_result)
		g_signal_handler_disconnect(proxy, p2p_signals->invitation_result);

	if (p2p_signals->invitation_received)
		g_signal_handler_disconnect(proxy, p2p_signals->invitation_received);

	if (p2p_signals->service_discovery_response)
		g_signal_handler_disconnect(proxy,
				p2p_signals->service_discovery_response);

	memset(p2p_signals, 0, sizeof(*p2p_signals));
}

void connect_p2p_signals(struct wpa_obj *obj)
{
	struct p2p_signals *p2p_signals = &obj->p2p_main_signals;
	wpainterfaceP2PDevice *proxy = obj->proxy_main_p2p;

	if (p2p_signals->dev_found)
	{
		logg_err("signals still initialized reset it");
		disconnect_p2p_signals(obj);
	}

	p2p_signals->dev_found = g_signal_connect (proxy,"device_found",
			G_CALLBACK (p2p_signal_device_found),
			obj);

	if (!p2p_signals->dev_found)
		logg_err("error init dev_found signal");

	p2p_signals->dev_found_prop =
			g_signal_connect (proxy,"device_found_properties",
					G_CALLBACK (p2p_signal_device_found_properties),
					obj);

	if (!p2p_signals->dev_found_prop)
		logg_err("error init dev_found_prop signal");

	p2p_signals->dev_lost =
			g_signal_connect(proxy, "device_lost", G_CALLBACK (p2p_signal_device_lost),
					obj);

	if (!p2p_signals->dev_lost)
		logg_err("error init dev_lost signal");

	p2p_signals->find_stopped = g_signal_connect (proxy,"find_stopped",
			G_CALLBACK (p2p_signal_find_stopped),
			obj);

	if (!p2p_signals->find_stopped)
		logg_err("error init find_stopped signal");

	p2p_signals->group_started = g_signal_connect (proxy,"group_started",
			G_CALLBACK (p2p_signal_group_started),
			obj);

	if (!p2p_signals->group_started)
		logg_err("error init group_started signal");

	p2p_signals->group_formation_failure =
			g_signal_connect (proxy,"group_formation_failure",
					G_CALLBACK (p2p_signal_group_formation_failure),
					obj);

	if (!p2p_signals->group_formation_failure)
		logg_err("error init group_formation_failure signal");

	p2p_signals->group_finished = g_signal_connect (proxy,"group_finished",
			G_CALLBACK (p2p_signal_group_finished),
			obj);

	if (!p2p_signals->group_finished)
		logg_err("error init group_finished signal");

	p2p_signals->gonegotiation_success =
			g_signal_connect (proxy,"gonegotiation_success",
					G_CALLBACK (p2p_signal_gonegotiation_success),
					obj);

	if (!p2p_signals->gonegotiation_success)
		logg_err("error init gonegotiation_success signal");

	p2p_signals->gonegotiation_request =
			g_signal_connect (proxy,"gonegotiation_request",
					G_CALLBACK (p2p_signal_gonegotiation_request),
					obj);

	if (!p2p_signals->gonegotiation_request)
		logg_err("error init gonegotiation_request signal");

	p2p_signals->gonegotiation_failure =
			g_signal_connect (proxy,"gonegotiation_failure",
					G_CALLBACK (p2p_signal_gonegotiation_failure),
					obj);

	if (!p2p_signals->gonegotiation_failure)
		logg_err("error init gonegotiation_failure signal");

	p2p_signals->wps_failed = g_signal_connect (proxy,"wps_failed",
			G_CALLBACK (p2p_signal_wps_failed),
			obj);

	if (!p2p_signals->gonegotiation_failure)
		logg_err("error init gonegotiation_failure signal");

	p2p_signals->service_discovery_response =
			g_signal_connect (proxy,"service_discovery_response",
					G_CALLBACK (p2p_signal_service_discovery_response),
					obj);

	if (!p2p_signals->gonegotiation_failure)
		logg_err("error init gonegotiation_failure signal");

	p2p_signals->service_discovery_request =
			g_signal_connect (proxy,"service_discovery_request",
					G_CALLBACK (p2p_signal_service_discovery_request),
					obj);

	if (!p2p_signals->gonegotiation_failure)
		logg_err("error init gonegotiation_failure signal");

	p2p_signals->provision_discovery_response_enter_pin =
			g_signal_connect (proxy,"provision_discovery_response_enter_pin",
					G_CALLBACK (p2p_signal_provision_discovery_response_enter_pin),
					obj);

	if (!p2p_signals->provision_discovery_response_enter_pin)
		logg_err("error init provision_discovery_response_enter_pin signal");

	p2p_signals->provision_discovery_response_display_pin =
			g_signal_connect (proxy,"provision_discovery_response_display_pin",
					G_CALLBACK (p2p_signal_provision_discovery_response_display_pin),
					obj);

	if (!p2p_signals->provision_discovery_response_display_pin)
		logg_err("error init provision_discovery_response_display_pin signal");

	p2p_signals->provision_discovery_request_enter_pin =
			g_signal_connect (proxy,"provision_discovery_request_enter_pin",
					G_CALLBACK (p2p_signal_provision_discovery_request_enter_pin),
					obj);

	if (!p2p_signals->provision_discovery_request_enter_pin)
		logg_err("error init provision_discovery_request_enter_pin signal");

	p2p_signals->provision_discovery_request_display_pin =
			g_signal_connect (proxy,"provision_discovery_request_display_pin",
					G_CALLBACK (p2p_signal_provision_discovery_request_display_pin),
					obj);

	if (!p2p_signals->provision_discovery_request_display_pin)
		logg_err("error init provision_discovery_request_display_pin signal");

	p2p_signals->provision_discovery_pbcresponse =
			g_signal_connect (proxy,"provision_discovery_pbcresponse",
					G_CALLBACK (p2p_signal_provision_discovery_pbcresponse),
					obj);

	if (!p2p_signals->provision_discovery_pbcresponse)
		logg_err("error init provision_discovery_pbcresponse signal");

	p2p_signals->provision_discovery_pbcrequest =
			g_signal_connect (proxy,"provision_discovery_pbcrequest",
					G_CALLBACK (p2p_signal_provision_discovery_pbcrequest),
					obj);

	if (!p2p_signals->provision_discovery_pbcrequest)
		logg_err("error init provision_discovery_pbcrequest signal");

	p2p_signals->provision_discovery_failure =
			g_signal_connect (proxy,"provision_discovery_failure",
					G_CALLBACK (p2p_signal_provision_discovery_failure),
					obj);

	if (!p2p_signals->provision_discovery_failure)
		logg_err("error init provision_discovery_failure signal");

	p2p_signals->persistent_group_removed =
			g_signal_connect (proxy,"persistent_group_removed",
					G_CALLBACK (p2p_signal_persistent_group_removed),
					obj);

	if (!p2p_signals->persistent_group_removed)
		logg_err("error init persistent_group_removed signal");

	p2p_signals->persistent_group_added =
			g_signal_connect (proxy,"persistent_group_added",
					G_CALLBACK (p2p_signal_persistent_group_added),
					obj);

	if (!p2p_signals->persistent_group_added)
		logg_err("error init persistent_group_added signal");

	p2p_signals->invitation_result =
			g_signal_connect (proxy,"invitation_result",
					G_CALLBACK (p2p_signal_invitation_result),
					obj);

	if (!p2p_signals->invitation_result)
		logg_err("error init invitation_result signal");

	p2p_signals->invitation_received =
			g_signal_connect (proxy,"invitation_received",
					G_CALLBACK (p2p_signal_invitation_received),
					obj);

	if (!p2p_signals->invitation_received)
		logg_err("error init invitation_received signal");

}

void destroy_hash_interface(gpointer data)
{
	struct interface_obj *interface_obj = (struct interface_obj *) data;

	g_free(interface_obj->name);
	g_object_unref(interface_obj->proxy);
	g_free(interface_obj);
}

void destroy_hash_group(gpointer data)
{
	struct group_obj *group_obj = (struct group_obj *) data;

	disconnect_group_signals(group_obj->proxy, &group_obj->group_signals);
	g_hash_table_destroy(group_obj->peers);
	g_object_unref(group_obj->proxy);
	g_free(group_obj->interface_obj_string);
	g_free(group_obj->role);
	g_free(group_obj);
}

int main(int argn, char *argv[])
{
	GError *err = NULL;

	struct wpa_obj wpa_obj =
	{ 0 };

	wpa_obj.hash_interface = g_hash_table_new_full(g_str_hash, g_str_equal,
			free_string, destroy_hash_interface);
	wpa_obj.hash_group = g_hash_table_new_full(g_str_hash, g_str_equal,
			free_string, destroy_hash_group);

	wpa_obj.dbus_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);

	if (err)
	{
		logg_err("Failed to acquire connection: %s", err->message);
		return -1;
	}

	wpa_obj.proxy_main_wpa = wpa_fi_w1_wpa_supplicant1_proxy_new_sync(
			wpa_obj.dbus_connection, G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME,
			WPA_SUP_PATH, NULL, &err);

	if (err)
	{
		logg_err("get wpa_proxy error %s", err->message);
		return -1;
	}

	gchar ** interfaces = wpa_fi_w1_wpa_supplicant1_dup_interfaces(
			wpa_obj.proxy_main_wpa);

	gchar **iter = interfaces;
	while (*iter)
	{
		logg(LOG_DEBUG, "remove interfaces: %s", *iter);


		if (!wpa_fi_w1_wpa_supplicant1_call_remove_interface_sync(
				wpa_obj.proxy_main_wpa, *iter, NULL, &err) || err)
		{
			logg_err("error remove interface %s: %s",
					*iter, err ? err->message : "");
			if (err)
				g_error_free(err);
		}

		iter++;
	}

	g_strfreev(interfaces);

//	if (!wpa_fi_w1_wpa_supplicant1_call_get_interface_sync(
//			wpa_obj.proxy_main_wpa, P2P_INTERFACE_NAME,
//			&wpa_obj.interface_obj_main_string, NULL, &err) || err)
//	{
//		logg_err("error get " P2P_INTERFACE_NAME" %s try to create interface",
//				err->message);
//		g_error_free(err);
//		err = NULL;

		if (!(wpa_obj.interface_obj_main_string =
				supplicant_create_interface_sync(wpa_obj.proxy_main_wpa,
						P2P_INTERFACE_NAME)))
			return -1;
//	}

	logg(LOG_DEBUG, "new main interface: %s", wpa_obj.interface_obj_main_string);

	wpa_fi_w1_wpa_supplicant1_set_debug_level(wpa_obj.proxy_main_wpa, "debug");

	supplicant_set_wfdie(wpa_obj.proxy_main_wpa, RTSP_TCP_CONTROL_PORT,
			DEV_MAX_AVERABE_THROUGHPUT_MBPS);

	wpa_obj.proxy_main_wps = wpa_interface_wps_proxy_new_sync(
			wpa_obj.dbus_connection, G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME,
			wpa_obj.interface_obj_main_string, NULL, &err);

	if (err)
	{
		logg_err("get iface wpa_proxy error %s", err->message);
		return -1;
	}

	wpa_interface_wps_set_config_methods(wpa_obj.proxy_main_wps, "push_button");

	wpa_obj.proxy_main_p2p = wpa_interface_p2_pdevice_proxy_new_sync(
			wpa_obj.dbus_connection, G_DBUS_PROXY_FLAGS_NONE, WPA_SUP_NAME,
			wpa_obj.interface_obj_main_string, NULL, &err);

	if (err)
	{
		logg_err("get p2p_dev wpa_proxy error %s", err->message);
		return -1;
	}

	supplicant_set_primary_dev_type(wpa_obj.proxy_main_p2p, DEVICE_NAME,
			GO_INTENT);

	supplicant_set_extended_listen(wpa_obj.proxy_main_p2p, 500, 2000);

	connect_p2p_signals(&wpa_obj);
	connect_wps_signals(&wpa_obj);
	connect_wpa_signals(&wpa_obj);

	if (!wpa_interface_p2_pdevice_call_listen_sync(wpa_obj.proxy_main_p2p, 5,
			NULL, &err) || err)
	{
		logg_err("Error call listen %s", err->message);
		return -1;
	}

	g_main_loop = g_main_loop_new(NULL, false);
	g_main_loop_run(g_main_loop);
	g_main_loop_unref(g_main_loop);

	disconnect_p2p_signals(&wpa_obj);
	disconnect_wps_signals(&wpa_obj);
	disconnect_wpa_signals(&wpa_obj);
	destroy_wpa_obj(&wpa_obj);
	return 0;

}
