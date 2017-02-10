/* packet-zepv3.c
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
 *------------------------------------------------------------
 *
 *      ZEP Packets must be received in the following format:
 *      |UDP Header|  ZEP Header |IEEE 802.15.4 Packet|
 *      | 8 bytes  | 16/32 bytes |    <= 127 bytes    |
 *------------------------------------------------------------
 *
 *      ZEP v1 Header will have the following format:
 *      |Preamble|Version|Channel ID|Device ID|CRC/LQI Mode|LQI Val|Reserved|Length|
 *      |2 bytes |1 byte |  1 byte  | 2 bytes |   1 byte   |1 byte |7 bytes |1 byte|
 *
 *      ZEP v2 Header will have the following format (if type=1/Data):
 *      |Preamble|Version| Type |Channel ID|Device ID|CRC/LQI Mode|LQI Val|NTP Timestamp|Sequence#|Reserved|Length|
 *      |2 bytes |1 byte |1 byte|  1 byte  | 2 bytes |   1 byte   |1 byte |   8 bytes   | 4 bytes |10 bytes|1 byte|
 *
 *      ZEP v2 Header will have the following format (if type=2/Ack):
 *      |Preamble|Version| Type |Sequence#|
 *      |2 bytes |1 byte |1 byte| 4 bytes |
 *
 *      ZEP v3 Header will have the following format (if type=1/Data):
 *      |Preamble|Version| Type |Channel ID|Device ID|CRC/LQI Mode|LQI Val|Relative Timestamp|Sequence#| Band |Channel page|Reserved|Length|
 *      |2 bytes |1 byte |1 byte|  1 byte  | 2 bytes |   1 byte   |1 byte |     8 bytes      | 4 bytes |1 byte|   1 byte   | 8 bytes|1 byte|
 *
 *      ZEP v3 Header will have the following format (if type=2/Ack):
 *      |Preamble|Version| Type |Sequence#|
 *      |2 bytes |1 byte |1 byte| 4 bytes |
 *------------------------------------------------------------
 */
//If source file is for dissector plugin, uncomment define below
#define PLUGIN

#include "config.h"

//#include <memory.h>

#include <string.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>
//#include <epan/nstime.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/tvbuff.h>
#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/etypes.h>
#include <epan/expert.h>

#include <wsutil/nstime.h>

#ifndef PLUGIN
#include "packet-ntp.h"

#endif

#include "packet-zepv3.h"

/*  Function declarations */
void proto_reg_handoff_zep(void);
void proto_register_zep(void);

/*  Initialize protocol and registered fields. */
static gint proto_zep = -1;
static gint hf_zep_id_string = -1;
static gint hf_zep_version = -1;
static gint hf_zep_type = -1;
static gint hf_zep_channel_id = -1;
static gint hf_zep_device_id = -1;
static gint hf_zep_lqi_mode = -1;
static gint hf_zep_lqi = -1;
static gint hf_zep_timestamp = -1;
static gint hf_zep_timestamprel = -1;
static gint hf_zep_seqno = -1;
static gint hf_zep_ieee_length = -1;
static gint hf_zep_abstimestamp = -1;
static gint hf_zep_reltimestamp = -1;
static gint hf_zep_diftimestamp = -1;
static gint hf_zep_refabstime = -1;

static gint hf_zep_band = -1;
static gint hf_zep_chanpage = -1;

/* Initialize protocol subtrees. */
static gint ett_zep = -1;

/* Initialize preferences. */
static const gchar *gPREF_nextdiss = "wpan";
static guint32  gPREF_zep_udp_port = ZEP_DEFAULT_PORT;
//static gboolean g_zep_timediff_filtered = TRUE;

#define DEV_TIMESTAMP_TYPE_RELATIVE	0
#define DEV_TIMESTAMP_TYPE_ABSOLUTE	1

static gint dev_timestamp_type = DEV_TIMESTAMP_TYPE_RELATIVE;

static const enum_val_t dev_timestamp_type_enums[] = {
    { "Relative_Time", "Relative timestamp", DEV_TIMESTAMP_TYPE_RELATIVE },
    { "Absolute_Time", "Absolute timestamp", DEV_TIMESTAMP_TYPE_ABSOLUTE },
    { NULL, NULL, 0 }
};
/*  Dissector handle */
static dissector_handle_t zep_handle;

/*  Subdissector handles */
static dissector_handle_t data_handle;
static dissector_handle_t ieee802154_handle;
static dissector_handle_t ieee802154_ccfcs_handle;




static const value_string bandstrings[] = {
    { 1, "780 MHz" },
    { 2, "868 MHz" },
    { 3, "915 MHz" },
    { 4, "2400 MHz" },
    { 5, "UWB Sub-gigahertz band" },
	{ 6, "UWB Low band" },
	{ 7, "UWB High band" },
    { 0,       NULL }
};

#ifdef PLUGIN

/* NTP_BASETIME is in fact epoch - ntp_start_time */
#define NTP_BASETIME 2208988800ul
#define NTP_FLOAT_DENOM 4294967296.0
#define NS_PER_S 1000000000

/*
 * function: nstime_delta
 * delta = b - a
 */

void _nstime_delta(nstime_t *delta, const nstime_t *b, const nstime_t *a )
{
    if (b->secs == a->secs) {
        /* The seconds part of b is the same as the seconds part of a, so if
           the nanoseconds part of the first time is less than the nanoseconds
           part of a, b is before a.  The nanoseconds part of the delta should
           just be the difference between the nanoseconds part of b and the
           nanoseconds part of a; don't adjust the seconds part of the delta,
           as it's OK if the nanoseconds part is negative, and an overflow
           can never result. */
        delta->secs = 0;
        delta->nsecs = b->nsecs - a->nsecs;
    } else if (b->secs <= a->secs) {
        /* The seconds part of b is less than the seconds part of a, so b is
           before a.

           Both the "seconds" and "nanoseconds" value of the delta
           should have the same sign, so if the difference between the
           nanoseconds values would be *positive*, subtract 1,000,000,000
           from it, and add one to the seconds value. */
        delta->secs = b->secs - a->secs;
        delta->nsecs = b->nsecs - a->nsecs;
        if(delta->nsecs > 0) {
            delta->nsecs -= NS_PER_S;
            delta->secs ++;
        }
    } else {
        delta->secs = b->secs - a->secs;
        delta->nsecs = b->nsecs - a->nsecs;
        if(delta->nsecs < 0) {
            delta->nsecs += NS_PER_S;
            delta->secs --;
        }
    }
}
/*
 * function: nstime_sum
 * sum = a + b
 */

void _nstime_sum(nstime_t *sum, const nstime_t *a, const nstime_t *b)
{
    sum->secs = a->secs + b->secs;
    sum->nsecs = a->nsecs + b->nsecs;
    if(sum->nsecs>=NS_PER_S || (sum->nsecs>0 && sum->secs<0)){
        sum->nsecs-=NS_PER_S;
        sum->secs++;
    } else if(sum->nsecs<=-NS_PER_S || (sum->nsecs<0 && sum->secs>0)) {
        sum->nsecs+=NS_PER_S;
        sum->secs--;
    }
}
/* set the given nstime_t to zero */
void _nstime_set_zero(nstime_t *nstime)
{
    nstime->secs  = 0;
    nstime->nsecs = 0;
}
 /*FUNCTION:------------------------------------------------------*/
void
ntp_to_nstime(tvbuff_t *tvb, gint offset, nstime_t *nstime)
{
	guint32		 tempstmp;

	/* We need a temporary variable here so the unsigned math
	 * works correctly (for years > 2036 according to RFC 2030
	 * chapter 3).
	 */
	tempstmp  = tvb_get_ntohl(tvb, offset);
	if (tempstmp)
		nstime->secs = tempstmp - (guint32)NTP_BASETIME;
	else
		nstime->secs = tempstmp; /* 0 */

	nstime->nsecs = (int)(tvb_get_ntohl(tvb, offset+4)/(NTP_FLOAT_DENOM/1000000000.0));
}


#endif
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zep
 *  DESCRIPTION
 *      IEEE 802.15.4 packet dissection routine for Wireshark.
 *  PARAMETERS
 *      tvbuff_t *tvb       - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree *tree    - pointer to data tree Wireshark uses to display packet.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static int dissect_zep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tvbuff_t            *next_tvb;
    proto_item          *proto_root, *pi;
    proto_tree          *zep_tree;
    guint8              ieee_packet_len;
    guint8              zep_header_len;
    zep_info            zep_data;

	conversation_t		*conversation;
    zep_conv_info_t		*zep_info;
	zep_transaction_t	*zep_trans;
	zep_proto_data_t    *proto_data;
	nstime_t			temp_time;

    dissector_handle_t  next_dissector;

	//g_warning("filter = %d, %d, %d, %d, %d",pinfo->fd->flags.visited,pinfo->fd->flags.ref_time,pinfo->fd->flags.marked,pinfo->fd->flags.ignored, pinfo->fd->prev_dis_num);
	//g_warning("Packet (%d):",pinfo->fd->num);

    /*  Determine whether this is a Q51/IEEE 802.15.4 sniffer packet or not */
    if(strcmp(tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 2, ENC_ASCII), ZEP_PREAMBLE)){
        /*  This is not a Q51/ZigBee sniffer packet */
        call_dissector(data_handle, tvb, pinfo, tree);
        return 0;
    }

    memset(&zep_data, 0, sizeof(zep_data)); /* Zero all zep_data fields. */

    /*  Extract the protocol version from the ZEP header. */
    zep_data.version = tvb_get_guint8(tvb, 2);
    if (zep_data.version == 1) {
        /* Type indicates a ZEP_v1 packet. */

        zep_header_len = ZEP_V1_HEADER_LEN;
        zep_data.type = 0;
        zep_data.channel_id = tvb_get_guint8(tvb, 3);
        zep_data.device_id = tvb_get_ntohs(tvb, 4);
        zep_data.lqi_mode = tvb_get_guint8(tvb, 6)?1:0;
        zep_data.lqi = tvb_get_guint8(tvb, 7);
        ieee_packet_len = (tvb_get_guint8(tvb, ZEP_V1_HEADER_LEN - 1) & ZEP_LENGTH_MASK);
    }
    else if(zep_data.version == 3){

        /*ZEP v3 native for Open Sniffer*/
        zep_data.type = tvb_get_guint8(tvb, 3);
        if (zep_data.type == ZEP_V3_TYPE_ACK) {
            /* ZEP Ack has only the seqno. */
            zep_header_len = ZEP_V3_ACK_LEN;
            zep_data.seqno = tvb_get_ntohl(tvb, 4);
            ieee_packet_len = 0;
        }
        else {
            /* Although, only type 1 corresponds to data, if another value is present, assume it is dissected the same. */
            zep_header_len = ZEP_V3_HEADER_LEN;
            zep_data.channel_id = tvb_get_guint8(tvb, 4);
            zep_data.device_id = tvb_get_ntohs(tvb, 5);
            zep_data.lqi_mode = tvb_get_guint8(tvb, 7)?1:0;
            zep_data.lqi = tvb_get_guint8(tvb, 8);

            //Relative timestamp
            zep_data.ntp_time.secs  = tvb_get_ntohl(tvb, 9);
	          zep_data.ntp_time.nsecs = (int)(tvb_get_ntohl(tvb, 9+4));

            zep_data.seqno = tvb_get_ntohl(tvb, 17);
            zep_data.band = tvb_get_guint8(tvb, 21);
            zep_data.chanpage = tvb_get_guint8(tvb, 22);
            ieee_packet_len = (tvb_get_guint8(tvb, ZEP_V3_HEADER_LEN - 1) & ZEP_LENGTH_MASK);
        }


    }
    else {
        /* At the time of writing, v2 is the latest version of ZEP, assuming
         * anything higher than v2 has identical format. */

        zep_data.type = tvb_get_guint8(tvb, 3);
        if (zep_data.type == ZEP_V2_TYPE_ACK) {
            /* ZEP Ack has only the seqno. */
            zep_header_len = ZEP_V2_ACK_LEN;
            zep_data.seqno = tvb_get_ntohl(tvb, 4);
            ieee_packet_len = 0;
        }
        else {
            /* Although, only type 1 corresponds to data, if another value is present, assume it is dissected the same. */
            zep_header_len = ZEP_V2_HEADER_LEN;
            zep_data.channel_id = tvb_get_guint8(tvb, 4);
            zep_data.device_id = tvb_get_ntohs(tvb, 5);
            zep_data.lqi_mode = tvb_get_guint8(tvb, 7)?1:0;
            zep_data.lqi = tvb_get_guint8(tvb, 8);
            ntp_to_nstime(tvb, 9, &(zep_data.ntp_time));
            zep_data.seqno = tvb_get_ntohl(tvb, 17);
            ieee_packet_len = (tvb_get_guint8(tvb, ZEP_V2_HEADER_LEN - 1) & ZEP_LENGTH_MASK);
        }
    }

#if 0
/*??dat*/
    if (zep_data.ntp_time.secs && zep_data.ntp_time.nsecs) {
        pinfo->fd->abs_ts = zep_data.ntp_time;
    }
#endif

    if(ieee_packet_len < tvb_reported_length(tvb)-zep_header_len){
        /* Packet's length is mis-reported, abort dissection */
        call_dissector(data_handle, tvb, pinfo, tree);
        return 0;
    }

    /*  Enter name info protocol field */
	col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "ZEPv%d",zep_data.version);

    /*  Enter name info protocol field */
    col_clear(pinfo->cinfo, COL_INFO);
    if (!((zep_data.version>=2) && (zep_data.type==ZEP_V2_TYPE_ACK))) col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated ZigBee Packet [Channel]=%i [Length]=%i", zep_data.channel_id, ieee_packet_len);
    else col_add_fstr(pinfo->cinfo, COL_INFO, "Ack, Sequence Number: %i", zep_data.seqno);

    //--------------------------------

	if(zep_data.version == 3){
		/* Available only in ZEP v3 */

		//Find or create conversation, base on: Captured sequence number, MAC addresses, UDP ports
		conversation = find_conversation(pinfo->fd->num, &pinfo->dl_src, &pinfo->dl_dst,PT_UDP,pinfo->srcport,pinfo->destport, 0);
		if(conversation == NULL){
			//g_warning("No-conv");
			conversation = conversation_new(pinfo->fd->num, &pinfo->dl_src, &pinfo->dl_dst,PT_UDP,pinfo->srcport,pinfo->destport, 0);
		}

		//Get space ford ata from conversation
		zep_info = (zep_conv_info_t *)conversation_get_proto_data(conversation, proto_zep);
		if(zep_info == NULL){
			//No data, create space for them
			//g_warning("No-zep_info");
			zep_info = wmem_new(wmem_file_scope(), zep_conv_info_t);
			zep_info ->pdus = wmem_tree_new(wmem_file_scope());
			conversation_add_proto_data(conversation,proto_zep,zep_info);
		}


		/* only TRUE first time we process this packet*/
		if (!pinfo->fd->flags.visited) {
			//Dissector not-visited

			//g_warning("not-visited");

			//Create data for local dissector
			proto_data = wmem_new(wmem_file_scope(), zep_proto_data_t);

			//
			//Saved data to conversation
			//

			//Look up for existing data
			zep_trans = (zep_transaction_t*)wmem_tree_lookup32(zep_info->pdus, zep_data.device_id);
			if(zep_trans){
				//Data exist
				//g_warning("zep_trans");

				proto_data->prev_dev_time = zep_trans->prev_dev_time;
				proto_data->is_first = FALSE;

				//g_warning("prev_seqno packet = %d",zep_trans->prev_seqno);

				//Save to Conversation:Device timestamp, ZEP sequence number
				zep_trans->prev_dev_time = zep_data.ntp_time;
				zep_trans->prev_seqno = zep_data.seqno;


				// Fill up and save data
			}else{
				//No data exits, This is first packet
				//g_warning("no-zep_trans");
				//g_warning("First packet");
				//Create, fill up and save data
				zep_trans = wmem_new(wmem_file_scope(), zep_transaction_t);

				//Save to Conversation: absolute time,Device timestamp, ZEP sequence number
				zep_trans->ref_time = pinfo->fd->abs_ts;
				zep_trans->first_dev_time = zep_data.ntp_time;
				zep_trans->prev_dev_time = zep_data.ntp_time;
				zep_trans->prev_seqno = zep_data.seqno;

				proto_data->prev_dev_time = zep_trans->prev_dev_time;
				proto_data->is_first = TRUE;

				//Save data to conversation
				wmem_tree_insert32(zep_info->pdus, zep_data.device_id, (void *)zep_trans);
			}

			proto_data->ref_time = zep_trans->ref_time;
			proto_data->first_dev_time = zep_trans->first_dev_time;

			//Saved local data
			p_add_proto_data(wmem_file_scope(),pinfo, proto_zep,zep_data.device_id, proto_data);

		}else{
			//Dissector visited
			//g_warning("visited");
			// get saved data from current dissector
			proto_data = (zep_proto_data_t *)p_get_proto_data(wmem_file_scope(),pinfo, proto_zep,zep_data.device_id);

			if(proto_data == NULL){
				//g_warning("no-proto_data");
			}

		}


		//-------------------------------

		//g_warning("prev_dis_num = %d",pinfo->fd->prev_dis_num);
		//	g_warning("frame_ref_num = %d",pinfo->fd->frame_ref_num);
		//g_warning("display = %d",(gint)pinfo->fd->flags.passed_dfilter);
		//g_warning("ignored = %d",(gint)pinfo->fd->flags.ignored);
		//g_warning("dependent_of_displayed = %d",(gint)pinfo->fd->flags.dependent_of_displayed);

      }


        //--------------------------------

    if(tree){
        /*  Create subtree for the ZEP Header */
        if (!((zep_data.version>=2) && (zep_data.type==ZEP_V2_TYPE_ACK))) {
            proto_root = proto_tree_add_protocol_format(tree, proto_zep, tvb, 0, zep_header_len, "ZigBee Encapsulation Protocol, Channel: %i, Length: %i", zep_data.channel_id, ieee_packet_len);
        }
        else {
            proto_root = proto_tree_add_protocol_format(tree, proto_zep, tvb, 0, zep_header_len, "ZigBee Encapsulation Protocol, Ack");
        }
        zep_tree = proto_item_add_subtree(proto_root, ett_zep);

        /*  Display the information in the subtree */
        proto_tree_add_item(zep_tree, hf_zep_id_string, tvb, 0, 2, ENC_ASCII|ENC_NA);
        if (zep_data.version==1) {
            proto_tree_add_uint(zep_tree, hf_zep_version, tvb, 2, 1, zep_data.version);
            proto_tree_add_uint(zep_tree, hf_zep_channel_id, tvb, 3, 1, zep_data.channel_id);
            proto_tree_add_uint(zep_tree, hf_zep_device_id, tvb, 4, 2, zep_data.device_id);
            proto_tree_add_boolean_format(zep_tree, hf_zep_lqi_mode, tvb, 6, 1, zep_data.lqi_mode, "LQI/CRC Mode: %s", zep_data.lqi_mode?"CRC":"LQI");
            if(!(zep_data.lqi_mode)){
                proto_tree_add_uint(zep_tree, hf_zep_lqi, tvb, 7, 1, zep_data.lqi);
            }
            proto_tree_add_subtree(zep_tree, tvb, 7+((zep_data.lqi_mode)?0:1), 7+((zep_data.lqi_mode)?1:0), ett_zep, NULL, "Reserved Fields");
        }else if (zep_data.version==3){

            /*
            *
            * ZEP version 3
            *
            */

            proto_tree_add_uint(zep_tree, hf_zep_version, tvb, 2, 1, zep_data.version);
            if (zep_data.type == ZEP_V2_TYPE_ACK) {
                proto_tree_add_uint_format(zep_tree, hf_zep_type, tvb, 3, 1, zep_data.type, "Type: %i (Ack)", ZEP_V2_TYPE_ACK);
                proto_tree_add_uint(zep_tree, hf_zep_seqno, tvb, 4, 4, zep_data.seqno);
            }
            else {
                proto_tree_add_uint_format(zep_tree, hf_zep_type, tvb, 3, 1, zep_data.type, "Type: %i (%s)", zep_data.type, (zep_data.type==ZEP_V2_TYPE_DATA)?"Data":"Reserved");
                proto_tree_add_uint(zep_tree, hf_zep_channel_id, tvb, 4, 1, zep_data.channel_id);
                proto_tree_add_uint(zep_tree, hf_zep_device_id, tvb, 5, 2, zep_data.device_id);
                proto_tree_add_boolean_format(zep_tree, hf_zep_lqi_mode, tvb, 7, 1, zep_data.lqi_mode, "LQI/CRC Mode: %s", zep_data.lqi_mode?"CRC":"LQI");
                if(!(zep_data.lqi_mode)){
                    proto_tree_add_uint(zep_tree, hf_zep_lqi, tvb, 8, 1, zep_data.lqi);
                }
                //-----------------------------------------------------


				switch (dev_timestamp_type) {
				case DEV_TIMESTAMP_TYPE_RELATIVE:
					/* Relative Timestamp */
					proto_tree_add_time(zep_tree, hf_zep_timestamprel, tvb, 9, 8, &(zep_data.ntp_time));
					break;
				case DEV_TIMESTAMP_TYPE_ABSOLUTE:
					/* Absolute Timestamp */
					proto_tree_add_time(zep_tree, hf_zep_timestamp, tvb, 9, 8, &(zep_data.ntp_time));
					break;
				}

				//
				//Compute absolute timestamp
                //

				//Relative time = Device Time - First Dev Time
				_nstime_delta(&temp_time,&zep_data.ntp_time,&proto_data->first_dev_time);
				proto_tree_add_time(zep_tree, hf_zep_reltimestamp, tvb, 9, 8, &(temp_time));

				//Absolute Time = Ref Absolute Time + Relative Time
				if(dev_timestamp_type == DEV_TIMESTAMP_TYPE_RELATIVE){
					_nstime_sum(&temp_time,&proto_data->ref_time,&temp_time);
					proto_tree_add_time(zep_tree, hf_zep_abstimestamp, tvb, 9, 8, &(temp_time));
				}
#if 0
				//Reference absolute time, frame timestamp of first packet in capture
				proto_tree_add_time(zep_tree, hf_zep_refabstime, tvb, 0, 0, &(proto_data->ref_time));
#endif
				if(proto_data->is_first){
					_nstime_set_zero(&temp_time);
                  pi = proto_tree_add_time(zep_tree, hf_zep_diftimestamp, tvb, 0, 0, &(temp_time));
                  proto_item_append_text(pi, " (First packet)");
                }else{

                  _nstime_delta(&temp_time,&zep_data.ntp_time,&proto_data->prev_dev_time);
                  proto_tree_add_time(zep_tree, hf_zep_diftimestamp, tvb, 0, 0, &(temp_time));

                }


                //----------------------------------------------------
                proto_tree_add_uint(zep_tree,hf_zep_seqno, tvb, 17, 4, zep_data.seqno);

                proto_tree_add_uint(zep_tree, hf_zep_band, tvb, 21, 1, zep_data.band);


                if(zep_data.chanpage == 255){
                  proto_tree_add_uint_format_value(zep_tree, hf_zep_chanpage, tvb, 22,1, zep_data.chanpage,"Not Defined (%d)",zep_data.chanpage);
                }else{
                  proto_tree_add_uint(zep_tree, hf_zep_chanpage, tvb, 22, 1, zep_data.chanpage);
                }

            }


        }
        else {
            proto_tree_add_uint(zep_tree, hf_zep_version, tvb, 2, 1, zep_data.version);
            if (zep_data.type == ZEP_V2_TYPE_ACK) {
                proto_tree_add_uint_format_value(zep_tree, hf_zep_type, tvb, 3, 1, zep_data.type, "%i (Ack)", ZEP_V2_TYPE_ACK);
                proto_tree_add_uint(zep_tree, hf_zep_seqno, tvb, 4, 4, zep_data.seqno);
            }
            else {
                proto_tree_add_uint_format_value(zep_tree, hf_zep_type, tvb, 3, 1, zep_data.type, "%i (%s)", zep_data.type, (zep_data.type==ZEP_V2_TYPE_DATA)?"Data":"Reserved");
                proto_tree_add_uint(zep_tree, hf_zep_channel_id, tvb, 4, 1, zep_data.channel_id);
                proto_tree_add_uint(zep_tree, hf_zep_device_id, tvb, 5, 2, zep_data.device_id);
                proto_tree_add_boolean_format(zep_tree, hf_zep_lqi_mode, tvb, 7, 1, zep_data.lqi_mode, "LQI/CRC Mode: %s", zep_data.lqi_mode?"CRC":"LQI");
                if(!(zep_data.lqi_mode)){
                    proto_tree_add_uint(zep_tree, hf_zep_lqi, tvb, 8, 1, zep_data.lqi);
                }
                pi = proto_tree_add_time(zep_tree, hf_zep_timestamp, tvb, 9, 8, &(zep_data.ntp_time));
                proto_item_append_text(pi, " (%ld.%09ds)", (long)zep_data.ntp_time.secs, zep_data.ntp_time.nsecs);
                proto_tree_add_uint(zep_tree, hf_zep_seqno, tvb, 17, 4, zep_data.seqno);
            }
        }
        if (!((zep_data.version==2) && (zep_data.type==ZEP_V2_TYPE_ACK))) proto_tree_add_uint_format_value(zep_tree, hf_zep_ieee_length, tvb, zep_header_len - 1, 1, ieee_packet_len, "%i %s", ieee_packet_len, (ieee_packet_len==1)?"Byte":"Bytes");
    }


    /* Determine which dissector to call next. */
    next_dissector = find_dissector(gPREF_nextdiss);
    if (!next_dissector) {
        /* IEEE 802.15.4 dissectors couldn't be found. */
        next_dissector = data_handle;
    }

    /*  Call the IEEE 802.15.4 dissector */
    if (!((zep_data.version>=2) && (zep_data.type==ZEP_V2_TYPE_ACK))) {
        next_tvb = tvb_new_subset_length(tvb, zep_header_len, ieee_packet_len);
        call_dissector(next_dissector, next_tvb, pinfo, tree);
    }

    if (zep_data.version == 3) {
        if (zep_data.type == ZEP_V3_TYPE_DATA) {
            return ZEP_V3_HEADER_LEN;
        } else if (zep_data.type == ZEP_V3_TYPE_ACK) {
            return ZEP_V3_ACK_LEN;
        }
    } else if (zep_data.version == 2) {
        if (zep_data.type == ZEP_V2_TYPE_DATA) {
            return ZEP_V2_HEADER_LEN;
        } else if (zep_data.type == ZEP_V2_TYPE_ACK) {
            return ZEP_V2_ACK_LEN;
        }
    } else if (zep_data.version == 1) {
        return ZEP_V1_HEADER_LEN;
    }

    return 0;
} /* dissect_ieee802_15_4 */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_register_zep
 *  DESCRIPTION
 *      IEEE 802.15.4 protocol registration routine.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_register_zep(void)
{
    module_t *zep_module;

    static hf_register_info hf[] = {
        { &hf_zep_id_string,
        { "Protocol ID String",           "zepv3.id_string", FT_STRING, BASE_NONE, NULL, 0x0,
            "The Protocol Identification string.", HFILL }},
        { &hf_zep_version,
        { "Protocol Version",           "zepv3.version", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The version of the sniffer.", HFILL }},

        { &hf_zep_type,
        { "Type",                       "zepv3.type", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_channel_id,
        { "Channel ID",                 "zepv3.channel_id", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The logical channel on which this packet was detected.", HFILL }},

        { &hf_zep_device_id,
        { "Device ID",                  "zepv3.device_id", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The ID of the device that detected this packet.", HFILL }},

        { &hf_zep_lqi_mode,
        { "LQI/CRC Mode",               "zepv3.lqi_mode", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Determines what format the last two bytes of the MAC frame use.", HFILL }},

        { &hf_zep_lqi,
        { "Link Quality Indication",    "zepv3.lqi", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_timestamp,
        { "Timestamp",                  "zepv3.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_timestamprel,
        { "Timestamp",                  "zepv3.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_abstimestamp,
        { "Absolute Timestamp",                  "zepv3.abstime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
          "Timestamp related to Wireshark. Based on Ethernet timestamp and Timestamp", HFILL }},

        { &hf_zep_reltimestamp,
        { "Relative Timestamp",                  "zepv3.reltime", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

        { &hf_zep_diftimestamp,
        { "Differential Timestamp",                  "zepv3.diftime", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Differential timestamp between current and previous packet.", HFILL }},

         { &hf_zep_refabstime,
        { "Reference Absolute Timestamp",         "zepv3.refatime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            NULL, HFILL }},


        { &hf_zep_seqno,
        { "Sequence Number",            "zepv3.seqno", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zep_ieee_length,
        { "Length",              "zepv3.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The length (in bytes) of the encapsulated IEEE 802.15.4 MAC frame.", HFILL }},
        { &hf_zep_band,
        { "Frequency band",            "zepv3.band", FT_UINT8, BASE_DEC, VALS(bandstrings), 0x0,
            "Frequency band.", HFILL }},

        { &hf_zep_chanpage,
        { "Channel page",            "zepv3.chanpage", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Channel page.", HFILL }},

	};

    static gint *ett[] = {
        &ett_zep
    };

    /*  Register protocol name and description. */
    proto_zep = proto_register_protocol("ZigBee Encapsulation Protocol version (v3)", "ZEPv3", "zepv3");
/*

    /Users/mgenti/Downloads/wireshark-2.2.2/plugins/zepv3/packet-zepv3.c:252:84: warning: unused parameter 'data' [-Wunused-parameter]
    static void dissect_zep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
    ^
    /Users/mgenti/Downloads/wireshark-2.2.2/plugins/zepv3/packet-zepv3.c:728:46: warning: incompatible pointer types passing 'void (tvbuff_t *, packet_info *, proto_tree *, void *)' (aka 'void (struct tvbuff *, struct _packet_info *, struct _proto_node *, void *)') to parameter of type 'dissector_t' (aka 'int (*)(struct tvbuff *, struct _packet_info *, struct _proto_node *, void *)') [-Wincompatible-pointer-types]
    zep_handle = register_dissector("zepv3", dissect_zep, proto_zep);
    ^~~~~~~~~~~
     /Users/mgenti/Downloads/wireshark-2.2.2/epan/packet.h:490:83: note: passing argument to parameter 'dissector' here
    WS_DLL_PUBLIC dissector_handle_t register_dissector(const char *name, dissector_t dissector, const int proto);
*/

    /*  Register header fields and subtrees. */
    proto_register_field_array(proto_zep, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*  Register preferences module */
    zep_module = prefs_register_protocol(proto_zep, proto_reg_handoff_zep);

    /*  Register preferences */
	prefs_register_string_preference(zep_module, "nextdiss", "Set next dissector as Link protocol",
                                     "Set next dissector with filter name",
                                     &gPREF_nextdiss);

    prefs_register_uint_preference(zep_module, "udp.port", "ZEP UDP port",
                 "Set the port for ZEP Protocol\n"
                 "Default port is 17754",
                 10, &gPREF_zep_udp_port);

	    prefs_register_enum_preference(zep_module, "dev_timestamp_type",
                                   "Display of Device Timestamp (only ZEP version 3)",
								   "Display Device Timestamp in seconds (Relative) or data and time (Absolute)",
                                   &dev_timestamp_type, dev_timestamp_type_enums, FALSE);

    /*  Register dissector with Wireshark. */
    zep_handle = register_dissector("zepv3", dissect_zep, proto_zep);
} /* proto_register_zep */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      proto_reg_handoff_zep
 *  DESCRIPTION
 *      Registers the zigbee dissector with Wireshark.
 *      Will be called every time 'apply' is pressed in the preferences menu.
 *  PARAMETERS
 *      none
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
void proto_reg_handoff_zep(void)
{
    static int                 lastPort;
    static gboolean            inited = FALSE;

    if ( !inited) {
        dissector_handle_t h;
        /* Get dissector handles. */
        if ( !(h = find_dissector("wpan")) ) { /* Try use built-in 802.15.4 disector */
            h = find_dissector("ieee802154");  /* otherwise use older 802.15.4 plugin disector */
        }
        ieee802154_handle = h;
        if ( !(h = find_dissector("wpan_cc24xx")) ) { /* Try use built-in 802.15.4 (Chipcon) disector */
            h = find_dissector("ieee802154_ccfcs");   /* otherwise use older 802.15.4 (Chipcon) plugin disector */
        }
        ieee802154_ccfcs_handle = h;
        data_handle = find_dissector("data");
        inited = TRUE;
    } else {
        /* If we were already registered, de-register our dissector
         * to free the port. */
        dissector_delete_uint("udp.port", lastPort, zep_handle);
    }

    /* Register our dissector. */
    dissector_add_uint("udp.port", gPREF_zep_udp_port, zep_handle);
    lastPort = gPREF_zep_udp_port;
} /* proto_reg_handoff_zep */

