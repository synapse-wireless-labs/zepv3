/* packet-zepv3.h
 * Dissector  routines for the ZigBee Encapsulation Protocol
 * By Owen Kirby <osk@exegin.com>, ZEPv3 added by Martin Leixner <info@sewio.net> Sewio Networks
 * Copyright 2009 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define ZEP_DEFAULT_PORT   17754

/*  ZEP Preamble Code */
#define ZEP_PREAMBLE        "EX"

/*  ZEP Header lengths. */
#define ZEP_V1_HEADER_LEN   16
#define ZEP_V2_HEADER_LEN   32
#define ZEP_V2_ACK_LEN      8

#define ZEP_V2_TYPE_DATA    1
#define ZEP_V2_TYPE_ACK     2

#define ZEP_V3_HEADER_LEN   32
#define ZEP_V3_ACK_LEN      8

#define ZEP_V3_TYPE_DATA    1
#define ZEP_V3_TYPE_ACK     2

#define ZEP_LENGTH_MASK     0x7F

typedef struct{
    guint8      version;
    guint8      type;
    guint8      channel_id;
    guint16     device_id;
    gboolean    lqi_mode;
    guint8      lqi;
    nstime_t    ntp_time;
    guint32     seqno;
    guint8      band;
    guint8      chanpage;
} zep_info;

#define KEY_ID     0x6578 // ASCII "EX"

/* Structure containing conversation specific information */
typedef struct _zep_conv_info_t {
	        wmem_tree_t *pdus;
} zep_conv_info_t;

/* Structure containing transaction specific information */
typedef struct _zep_transaction_t {
	      nstime_t  ref_time;
          nstime_t  first_dev_time;
          guint32   prev_seqno;
          //gboolean  is_first;
          nstime_t  prev_dev_time;
	} zep_transaction_t;
  
typedef struct {
  //guint32  key;
  nstime_t ref_time;
  nstime_t  first_dev_time;
  gboolean  is_first;
  nstime_t prev_dev_time;
} zep_proto_data_t;
