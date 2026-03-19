/*
 * at_custom_zigbee_cmd.h — IEEE 802.15.4 Sniffer AT Commands
 */

#ifndef AT_CUSTOM_ZIGBEE_CMD_H
#define AT_CUSTOM_ZIGBEE_CMD_H

#include <stdbool.h>

/**
 * Register IEEE 802.15.4 sniffer AT commands:
 *   AT+ZIGSNIFF=1,<ch>  Start sniffing on channel 11-26
 *   AT+ZIGSNIFF=0       Stop sniffing
 *   AT+ZIGSNIFF?        Query status
 *
 * Captured frames output as:
 *   +ZIGFRAME:<proto>,<ftype>,<len>,<ch>,<rssi>,<lqi>,<dst_pan>,<dst_addr>,<src_pan>,<src_addr>,<hex>
 *   proto: Z=Zigbee, T=Thread, U=unknown
 *   ftype: BCN, DATA, ACK, CMD
 */
bool esp_at_custom_zigbee_cmd_register(void);

#endif /* AT_CUSTOM_ZIGBEE_CMD_H */
