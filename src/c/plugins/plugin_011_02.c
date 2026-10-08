//*************************************************************************
// JANUS plugin for class user ID 11 (Text messages),                    *
// application type 2 (Generic Text Chat), ANEP-87 Annex D, Table XXIX.   *
//*************************************************************************
// This is free software: you can redistribute it and/or modify it        *
// under the terms of the GNU General Public License version 3 as         *
// published by the Free Software Foundation.                             *
//                                                                        *
// This program is distributed in the hope that it will be useful, but    *
// WITHOUT ANY WARRANTY; without even the implied warranty of FITNESS     *
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for       *
// more details.                                                          *
//                                                                        *
// You should have received a copy of the GNU General Public License      *
// along with this program. If not, see <http://www.gnu.org/licenses/>.   *
//*************************************************************************
// Built by the CMake glob plugin_*_*.c as libplugin_011_02.so, like     *
// plugin_016_00.                                                         *
//*************************************************************************

// ISO C headers.
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// JANUS headers.
#include <janus/defaults.h>
#include <janus/codec/codec.h>
#include <janus/crc.h>
#include <janus/error.h>
#include <janus/utils/memory.h>

#define STATION_ID_LABEL "StationIdentifier"
#define DESTINATION_ID_LABEL "DestinationIdentifier"
#define CODING_LABEL "Coding"
#define ENCRYPTION_LABEL "Encryption"
#define PAYLOAD_SIZE_LABEL "Payload Size"
#define PAYLOAD_LABEL "Payload"

// With the schedule flag set the ADB is 26 bits (packet bits 31-56).
#define ADB_SIZE 26
// Bit offsets inside the 26-bit ADB (bit 0 = packet bit 56).
#define CARGO_LEN_SHIFT 19 // 7 bits: granularity (2) + elements (5)
#define STATION_ID_SHIFT 11 // 8 bits
#define DESTINATION_ID_SHIFT 3 // 8 bits
#define CODING_SHIFT 2 // 1 bit
#define ENCRYPTION_SHIFT 0 // 2 bits

#define BROADCAST_ID 255
#define MAX_STATION_ID 254
#define CRC16_SIZE 2
#define MAX_CARGO_SIZE 480
#define MAX_TEXT_SIZE (MAX_CARGO_SIZE - CRC16_SIZE)

// Cargo length = base + step * (x + 1), x in [0, 31], per granularity g.
static const unsigned c_len_step[4] = {1, 2, 4, 8};
static const unsigned c_len_base[4] = {0, 32, 96, 224};

//! Cargo length from granularity g and number of elements x.
static inline unsigned
cargo_len_decode(unsigned g, unsigned x)
{
  return c_len_base[g] + c_len_step[g] * (x + 1);
}

//! Smallest representable cargo length >= size (0 if size > 480).
static inline unsigned
cargo_len_round(unsigned size, unsigned* g, unsigned* x)
{
  unsigned i;
  if (size == 0 || size > MAX_CARGO_SIZE)
    return 0;
  for (i = 0; i < 4; ++i)
  {
    unsigned max = c_len_base[i] + c_len_step[i] * 32;
    if (size <= max)
    {
      unsigned elems = (size <= c_len_base[i]) ? 1 : (size - c_len_base[i] + c_len_step[i] - 1) / c_len_step[i];
      *g = i;
      *x = elems - 1;
      return cargo_len_decode(i, elems - 1);
    }
  }
  return 0;
}

//! CRC16 x^16+x^15+x^2+1 (CRC-16/ARC: reflected, init 0).
static inline janus_uint16_t
text_crc16(const janus_uint8_t* data, unsigned len)
{
  return janus_crc_16(data, len, 0);
}

static inline const char*
find_field(janus_app_fields_t app_fields, const char* name)
{
  int i;
  if (app_fields == 0)
    return 0;
  for (i = 0; i < app_fields->field_count; ++i)
  {
    if (strcmp(app_fields->fields[i].name, name) == 0)
      return app_fields->fields[i].value;
  }
  return 0;
}

static inline void
add_uint_field(janus_app_fields_t app_fields, const char* name, unsigned value)
{
  char str[12];
  sprintf(str, "%u", value);
  janus_app_fields_add_field(app_fields, name, str);
}

JANUS_PLUGIN_EXPORT int
app_data_decode(janus_uint64_t app_data, janus_uint8_t app_data_size, unsigned* cargo_size, janus_app_fields_t app_fields)
{
  // The schedule flag must be set (reservation), leaving 26 ADB bits.
  if (app_data_size != ADB_SIZE)
    return JANUS_ERROR_FIELDS;

  unsigned len = (unsigned)((app_data >> CARGO_LEN_SHIFT) & 0x7FU);
  add_uint_field(app_fields, STATION_ID_LABEL, (unsigned)((app_data >> STATION_ID_SHIFT) & 0xFFU));
  add_uint_field(app_fields, DESTINATION_ID_LABEL, (unsigned)((app_data >> DESTINATION_ID_SHIFT) & 0xFFU));
  add_uint_field(app_fields, CODING_LABEL, (unsigned)((app_data >> CODING_SHIFT) & 0x1U));
  add_uint_field(app_fields, ENCRYPTION_LABEL, (unsigned)((app_data >> ENCRYPTION_SHIFT) & 0x3U));

  *cargo_size = cargo_len_decode(len >> 5, len & 0x1FU);

  return 0;
}

JANUS_PLUGIN_EXPORT int
app_data_encode(unsigned desired_cargo_size, janus_app_fields_t app_fields, janus_uint8_t app_data_size, unsigned* cargo_size, janus_uint64_t* app_data)
{
  unsigned g, x;
  const char* value;
  janus_uint64_t station_id, destination_id = BROADCAST_ID, coding = 0, encryption = 0;

  *app_data = 0;

  // The schedule flag must be set (reservation), leaving 26 ADB bits.
  // On TX libjanus does not update app_data_size before encoding (0 for a
  // new packet), so only an explicit 34-bit ADB is rejected here: the caller
  // must set the reservation time. The 26 bits land in the same packet bits
  // (31-56) in both layouts.
  if (app_data_size != ADB_SIZE && app_data_size != 0)
    return JANUS_ERROR_FIELDS;

  // The cargo (text + padding + CRC16) must have a representable length.
  if (cargo_len_round(desired_cargo_size, &g, &x) != desired_cargo_size)
    return JANUS_ERROR_CARGO_SIZE;

  value = find_field(app_fields, STATION_ID_LABEL);
  if (value == 0)
    return JANUS_ERROR_FIELDS;
  station_id = atoi(value);
  if (station_id > MAX_STATION_ID)
    return JANUS_ERROR_FIELDS;

  if ((value = find_field(app_fields, DESTINATION_ID_LABEL)) != 0)
    destination_id = atoi(value) & 0xFFU;
  if ((value = find_field(app_fields, CODING_LABEL)) != 0)
    coding = atoi(value) & 0x1U;
  if ((value = find_field(app_fields, ENCRYPTION_LABEL)) != 0)
    encryption = atoi(value) & 0x3U;

  *app_data = ((janus_uint64_t)((g << 5) | x) << CARGO_LEN_SHIFT)
    | (station_id << STATION_ID_SHIFT)
    | (destination_id << DESTINATION_ID_SHIFT)
    | (coding << CODING_SHIFT)
    | (encryption << ENCRYPTION_SHIFT);
  *cargo_size = desired_cargo_size;

  return 0;
}

JANUS_PLUGIN_EXPORT int
cargo_decode(janus_uint8_t* cargo, unsigned cargo_size, janus_app_fields_t* app_fields)
{
  unsigned text_size;
  janus_uint16_t crc;

  if (cargo_size <= CRC16_SIZE)
    return JANUS_ERROR_CARGO_SIZE;

  // CRC16 (big-endian) over text and padding.
  text_size = cargo_size - CRC16_SIZE;
  crc = (janus_uint16_t)((cargo[text_size] << 8) | cargo[text_size + 1]);
  if (crc != text_crc16(cargo, text_size))
    return JANUS_ERROR_CARGO_CORRUPTED;

  // Zero padding: the text is a zero terminated string.
  while (text_size > 0 && cargo[text_size - 1] == 0)
    --text_size;

  if (*app_fields == 0)
    *app_fields = janus_app_fields_new();

  add_uint_field(*app_fields, PAYLOAD_SIZE_LABEL, text_size);
  janus_app_fields_add_blob(*app_fields, PAYLOAD_LABEL, cargo, text_size);

  return 0;
}

JANUS_PLUGIN_EXPORT int
cargo_encode(janus_app_fields_t app_fields, janus_uint8_t** cargo, unsigned* cargo_size)
{
  unsigned g, x, text_size, total;
  janus_uint16_t crc;
  const char* text = find_field(app_fields, PAYLOAD_LABEL);
  const char* size = find_field(app_fields, PAYLOAD_SIZE_LABEL);

  if (text == 0)
    return JANUS_ERROR_FIELDS;

  text_size = (size != 0) ? (unsigned)atoi(size) : (unsigned)strlen(text);
  // Field values are zero terminated strings: no zero bytes in the text.
  if (text_size == 0 || text_size > strlen(text))
    return JANUS_ERROR_FIELDS;
  if (text_size > MAX_TEXT_SIZE)
    return JANUS_ERROR_CARGO_SIZE;

  // text | zero padding | CRC16, with a representable total length.
  total = cargo_len_round(text_size + CRC16_SIZE, &g, &x);
  *cargo = JANUS_UTILS_MEMORY_REALLOC(*cargo, janus_uint8_t, total);
  memset(*cargo, 0, total);
  memcpy(*cargo, text, text_size);
  crc = text_crc16(*cargo, total - CRC16_SIZE);
  (*cargo)[total - 2] = (janus_uint8_t)(crc >> 8);
  (*cargo)[total - 1] = (janus_uint8_t)(crc & 0xFF);
  *cargo_size = total;

  return 0;
}
