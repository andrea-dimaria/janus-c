//*************************************************************************
// JANUS plugin for class user ID 0 (Emergency),                          *
// application type 1 (Emergency Position), ANEP-87 Annex D, Tables IV-V. *
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
// Built by the CMake glob plugin_*_*.c as libplugin_000_01.so, like     *
// plugin_016_00.                                                         *
//                                                                        *
// Fields (physical units, decimal strings):                              *
//   StationIdentifier [0, 254] (required), DestinationIdentifier [0, 255]*
//   (default 255 = broadcast), Latitude [-90, 90] deg and Longitude      *
//   [-180, 180] deg (required), Depth m, Speed kn, Heading deg,          *
//   Nationality (two letters, ISO 3166) (optional: "not available").     *
// On RX the optional fields are present only when available.            *
//*************************************************************************

// ISO C headers.
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

// JANUS headers.
#include <janus/defaults.h>
#include <janus/codec/codec.h>
#include <janus/crc.h>
#include <janus/error.h>
#include <janus/utils/memory.h>

#define STATION_ID_LABEL "StationIdentifier"
#define DESTINATION_ID_LABEL "DestinationIdentifier"
#define LATITUDE_LABEL "Latitude"
#define LONGITUDE_LABEL "Longitude"
#define DEPTH_LABEL "Depth"
#define SPEED_LABEL "Speed"
#define HEADING_LABEL "Heading"
#define NATIONALITY_LABEL "Nationality"

// With the schedule flag set the ADB is 26 bits (packet bits 31-56).
#define ADB_SIZE 26
// Bit offsets inside the 26-bit ADB (bit 0 = packet bit 56); bit 25 unused.
#define STATION_ID_SHIFT 17 // 8 bits
#define DESTINATION_ID_SHIFT 9 // 8 bits
#define CARGO_SIZE_MASK 0x1FFU // 9 bits

#define BROADCAST_ID 255
#define MAX_STATION_ID 254
#define CARGO_SIZE 14 // 112 bits (Table V)
#define CRC_OFFSET 12 // CRC16 over the first 96 bits

// Table V field widths and "not available" values.
#define NATIONALITY_BITS 10
#define LATITUDE_BITS 24
#define LONGITUDE_BITS 25
#define DEPTH_BITS 13
#define SPEED_BITS 9
#define HEADING_BITS 9
#define NATIONALITY_NA 0x3FFU
#define DEPTH_NA 8191U
#define SPEED_NA 511U
#define HEADING_NA 511U
#define LATLON_SCALE (8388607.0 / 90.0) // units per degree
#define SPEED_STEP 0.1 // kn
#define HEADING_STEP 0.705 // deg

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

static inline void
add_real_field(janus_app_fields_t app_fields, const char* name, const char* format, double value)
{
  char str[24];
  snprintf(str, sizeof(str), format, value);
  janus_app_fields_add_field(app_fields, name, str);
}

//! Parse a decimal number, the whole string must be used.
static inline int
parse_real(const char* str, double* value)
{
  char* end;
  if (str == 0 || *str == 0)
    return 0;
  *value = strtod(str, &end);
  return *end == 0 && *value == *value && *value > -1e9 && *value < 1e9;
}

//! Round to nearest, halfway cases away from zero (Annex D mapping rules).
//! No libm: plugins are linked with -nostdlib.
static inline long
round_away(double value)
{
  return (value < 0) ? -(long)(-value + 0.5) : (long)(value + 0.5);
}

//! Write the n lowest bits of value at bit position *pos (MSB first).
static inline void
put_bits(janus_uint8_t* data, unsigned* pos, janus_uint32_t value, unsigned n)
{
  while (n-- > 0)
  {
    if ((value >> n) & 1U)
      data[*pos / 8] |= (janus_uint8_t)(0x80U >> (*pos % 8));
    ++(*pos);
  }
}

//! Read n bits at bit position *pos (MSB first).
static inline janus_uint32_t
get_bits(const janus_uint8_t* data, unsigned* pos, unsigned n)
{
  janus_uint32_t value = 0;
  while (n-- > 0)
  {
    value = (value << 1) | ((data[*pos / 8] >> (7 - *pos % 8)) & 1U);
    ++(*pos);
  }
  return value;
}

//! Sign extension of an n-bit two's complement value.
static inline long
to_signed(janus_uint32_t value, unsigned n)
{
  return (value & (1U << (n - 1))) ? (long)value - (1L << n) : (long)value;
}

//! CRC16 x^16+x^15+x^2+1 (CRC-16/ARC: reflected, init 0), as class 11.
static inline janus_uint16_t
position_crc16(const janus_uint8_t* data, unsigned len)
{
  return janus_crc_16(data, len, 0);
}

JANUS_PLUGIN_EXPORT int
app_data_decode(janus_uint64_t app_data, janus_uint8_t app_data_size, unsigned* cargo_size, janus_app_fields_t app_fields)
{
  // The schedule flag must be set (reservation), leaving 26 ADB bits.
  if (app_data_size != ADB_SIZE)
    return JANUS_ERROR_FIELDS;

  add_uint_field(app_fields, STATION_ID_LABEL, (unsigned)((app_data >> STATION_ID_SHIFT) & 0xFFU));
  add_uint_field(app_fields, DESTINATION_ID_LABEL, (unsigned)((app_data >> DESTINATION_ID_SHIFT) & 0xFFU));

  *cargo_size = (unsigned)(app_data & CARGO_SIZE_MASK);
  if (*cargo_size != CARGO_SIZE)
    return JANUS_ERROR_CARGO_SIZE;

  return 0;
}

JANUS_PLUGIN_EXPORT int
app_data_encode(unsigned desired_cargo_size, janus_app_fields_t app_fields, janus_uint8_t app_data_size, unsigned* cargo_size, janus_uint64_t* app_data)
{
  const char* value;
  janus_uint64_t station_id, destination_id = BROADCAST_ID;

  *app_data = 0;

  // The schedule flag must be set (reservation), leaving 26 ADB bits; on TX
  // libjanus passes 0 here (see plugin_011_02.c).
  if (app_data_size != ADB_SIZE && app_data_size != 0)
    return JANUS_ERROR_FIELDS;

  if (desired_cargo_size != CARGO_SIZE)
    return JANUS_ERROR_CARGO_SIZE;

  value = find_field(app_fields, STATION_ID_LABEL);
  if (value == 0)
    return JANUS_ERROR_FIELDS;
  station_id = atoi(value);
  if (station_id > MAX_STATION_ID)
    return JANUS_ERROR_FIELDS;

  if ((value = find_field(app_fields, DESTINATION_ID_LABEL)) != 0)
    destination_id = atoi(value) & 0xFFU;

  *app_data = (station_id << STATION_ID_SHIFT)
    | (destination_id << DESTINATION_ID_SHIFT)
    | CARGO_SIZE;
  *cargo_size = CARGO_SIZE;

  return 0;
}

JANUS_PLUGIN_EXPORT int
cargo_decode(janus_uint8_t* cargo, unsigned cargo_size, janus_app_fields_t* app_fields)
{
  unsigned pos = 0;
  janus_uint32_t nationality, depth, speed, heading;
  long latitude, longitude;
  janus_uint16_t crc;

  if (cargo_size != CARGO_SIZE)
    return JANUS_ERROR_CARGO_SIZE;

  // CRC16 (big-endian) over the 96 bits before it.
  crc = (janus_uint16_t)((cargo[CRC_OFFSET] << 8) | cargo[CRC_OFFSET + 1]);
  if (crc != position_crc16(cargo, CRC_OFFSET))
    return JANUS_ERROR_CARGO_CORRUPTED;

  nationality = get_bits(cargo, &pos, NATIONALITY_BITS);
  latitude = to_signed(get_bits(cargo, &pos, LATITUDE_BITS), LATITUDE_BITS);
  longitude = to_signed(get_bits(cargo, &pos, LONGITUDE_BITS), LONGITUDE_BITS);
  depth = get_bits(cargo, &pos, DEPTH_BITS);
  speed = get_bits(cargo, &pos, SPEED_BITS);
  heading = get_bits(cargo, &pos, HEADING_BITS);

  if (*app_fields == 0)
    *app_fields = janus_app_fields_new();

  add_real_field(*app_fields, LATITUDE_LABEL, "%.6f", latitude / LATLON_SCALE);
  add_real_field(*app_fields, LONGITUDE_LABEL, "%.6f", longitude / LATLON_SCALE);
  if (depth != DEPTH_NA)
    add_uint_field(*app_fields, DEPTH_LABEL, depth);
  if (speed != SPEED_NA)
    add_real_field(*app_fields, SPEED_LABEL, "%.1f", speed * SPEED_STEP);
  if (heading != HEADING_NA)
    add_real_field(*app_fields, HEADING_LABEL, "%.1f", heading * HEADING_STEP);
  if (nationality != NATIONALITY_NA)
  {
    unsigned c1 = nationality >> 5, c2 = nationality & 0x1FU;
    if (c1 >= 1 && c1 <= 26 && c2 >= 1 && c2 <= 26)
    {
      char code[3] = {(char)('A' + c1 - 1), (char)('A' + c2 - 1), 0};
      janus_app_fields_add_field(*app_fields, NATIONALITY_LABEL, code);
    }
  }

  return 0;
}

JANUS_PLUGIN_EXPORT int
cargo_encode(janus_app_fields_t app_fields, janus_uint8_t** cargo, unsigned* cargo_size)
{
  unsigned pos = 0;
  double lat, lon, value;
  janus_uint32_t nationality = NATIONALITY_NA, depth = DEPTH_NA, speed = SPEED_NA, heading = HEADING_NA;
  long ilat, ilon;
  const char* str;
  janus_uint16_t crc;

  if (!parse_real(find_field(app_fields, LATITUDE_LABEL), &lat) || lat < -90.0 || lat > 90.0)
    return JANUS_ERROR_FIELDS;
  if (!parse_real(find_field(app_fields, LONGITUDE_LABEL), &lon) || lon < -180.0 || lon > 180.0)
    return JANUS_ERROR_FIELDS;
  ilat = round_away(lat * LATLON_SCALE);
  ilon = round_away(lon * LATLON_SCALE);
  // +90 and +180 deg are one unit beyond the positive range
  if (ilat > 8388607L) ilat = 8388607L;
  if (ilon > 16777215L) ilon = 16777215L;

  if ((str = find_field(app_fields, DEPTH_LABEL)) != 0)
  {
    if (!parse_real(str, &value) || value < 0)
      return JANUS_ERROR_FIELDS;
    depth = (value >= DEPTH_NA) ? DEPTH_NA : (janus_uint32_t)round_away(value);
  }
  if ((str = find_field(app_fields, SPEED_LABEL)) != 0)
  {
    if (!parse_real(str, &value) || value < 0)
      return JANUS_ERROR_FIELDS;
    speed = (value >= SPEED_NA * SPEED_STEP) ? SPEED_NA : (janus_uint32_t)round_away(value / SPEED_STEP);
  }
  if ((str = find_field(app_fields, HEADING_LABEL)) != 0)
  {
    if (!parse_real(str, &value) || value < 0 || value >= 360.0)
      return JANUS_ERROR_FIELDS;
    heading = (janus_uint32_t)round_away(value / HEADING_STEP);
    // 511 means "not available": 359.9 deg would round onto it
    if (heading >= HEADING_NA)
      heading = 0;
  }
  if ((str = find_field(app_fields, NATIONALITY_LABEL)) != 0)
  {
    // two letters, 5 bits each with the two MSBs of ASCII masked
    if (strlen(str) != 2 || !isalpha((unsigned char)str[0]) || !isalpha((unsigned char)str[1]))
      return JANUS_ERROR_FIELDS;
    nationality = ((janus_uint32_t)(toupper((unsigned char)str[0]) & 0x1F) << 5)
      | (janus_uint32_t)(toupper((unsigned char)str[1]) & 0x1F);
  }

  *cargo = JANUS_UTILS_MEMORY_REALLOC(*cargo, janus_uint8_t, CARGO_SIZE);
  memset(*cargo, 0, CARGO_SIZE);
  put_bits(*cargo, &pos, nationality, NATIONALITY_BITS);
  put_bits(*cargo, &pos, (janus_uint32_t)ilat & 0xFFFFFFU, LATITUDE_BITS);
  put_bits(*cargo, &pos, (janus_uint32_t)ilon & 0x1FFFFFFU, LONGITUDE_BITS);
  put_bits(*cargo, &pos, depth, DEPTH_BITS);
  put_bits(*cargo, &pos, speed, SPEED_BITS);
  put_bits(*cargo, &pos, heading, HEADING_BITS);
  // 6 bits of zero padding, then the CRC16 (big-endian)
  crc = position_crc16(*cargo, CRC_OFFSET);
  (*cargo)[CRC_OFFSET] = (janus_uint8_t)(crc >> 8);
  (*cargo)[CRC_OFFSET + 1] = (janus_uint8_t)(crc & 0xFF);
  *cargo_size = CARGO_SIZE;

  return 0;
}
