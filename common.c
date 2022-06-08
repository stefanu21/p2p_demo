#include "common.h"

void
common_miracast_obj_destroy(struct miracast_obj_t *obj)
{
  g_free(obj->pin_peer_obj_string);
}

char *
common_byte_array_to_string(GVariant *variant, gboolean as_mac)
{
  GVariantIter iter;
  gchar value;
  gsize nr_bytes, size;
  gchar *buffer, *p_buffer;
  gboolean first = true;

  if (!variant) {
    logg_err("variant NULL");
    return NULL;
  }

  nr_bytes = g_variant_iter_init(&iter, variant);

  if (as_mac) {
    if (nr_bytes != 6) {
      logg_err("unexpected size %lu", nr_bytes);
      return NULL;
    }

    size = 6 * 3; // xx:xx:xx:xx:xx:xx\n
  } else
    size = nr_bytes + 1;

  buffer = calloc(size, sizeof(*buffer));
  p_buffer = buffer;

  while (g_variant_iter_next(&iter, "y", &value) && nr_bytes--) {
    if (as_mac) {
      if (first) {
        first = false;
        snprintf(p_buffer, size, "%02X", (guchar) value);
        p_buffer += 2;
        size -= 2;
      } else {
        snprintf(p_buffer, size, ":%02X", (guchar) value);
        p_buffer += 3;
        size -= 3;
      }
    } else
      *(p_buffer++) = (gchar) value;
  }

  return buffer;
}

