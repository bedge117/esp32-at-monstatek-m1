/*
 * at_custom_hid_cmd.h — BLE HID Keyboard AT Commands
 */

#ifndef AT_CUSTOM_HID_CMD_H
#define AT_CUSTOM_HID_CMD_H

#include <stdbool.h>

/**
 * Register BLE HID AT commands:
 *   AT+BLEHIDINIT=<mode>          Initialize/deinitialize HID (1=enable, 0=disable)
 *   AT+BLEHIDINIT?                Query HID initialization state
 *   AT+BLEHIDADV=<enable>         Start/stop HID advertising (1=start, 0=stop)
 *   AT+BLEHIDKB=<mod>,<k1>,...    Send keyboard report (modifier + 6 keycodes)
 */
bool esp_at_custom_hid_cmd_register(void);

#endif /* AT_CUSTOM_HID_CMD_H */
