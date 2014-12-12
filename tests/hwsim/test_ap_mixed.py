# Mixed AP module parameters enabled
# Copyright (c) 2014, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

import hostapd
import hwsim_utils

def test_ap_mixed_security(dev, apdev):
    """WPA/WPA2 with PSK, EAP, SAE, FT in a single BSS"""
    ssid = "test-mixed"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa_mixed_params(ssid=ssid, passphrase=passphrase)
    params['wpa_key_mgmt'] = "WPA-PSK WPA-PSK-SHA256 WPA-EAP WPA-EAP-SHA256 SAE FT-PSK FT-EAP FT-SAE"
    params["ieee8021x"] = "1"
    params["eap_server"] = "1"
    params["eap_user_file"] = "auth_serv/eap_user.conf"
    params['nas_identifier'] = "nas1.w1.fi"
    hapd = hostapd.add_ap(apdev[0]['ifname'], params)

    dev[0].connect(ssid, key_mgmt="WPA-PSK", proto="WPA", pairwise="TKIP",
                   psk=passphrase, scan_freq="2412")
    dev[1].connect(ssid, key_mgmt="WPA-EAP-SHA256", proto="WPA2", eap="GPSK",
                   identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")
    dev[2].connect(ssid, psk=passphrase, key_mgmt="SAE", scan_freq="2412")

    bss = dev[0].get_bss(apdev[0]['bssid'])
    if "[WPA-EAP+PSK-TKIP]" not in bss['flags']:
        raise Exception("Unexpected flags (WPA): " + bss['flags'])
    if "[WPA2-EAP+PSK+SAE+FT/EAP+FT/PSK+FT/SAE+EAP-SHA256+PSK-SHA256-CCMP]" not in bss['flags']:
        raise Exception("Unexpected flags (WPA2): " + bss['flags'])

    if dev[0].get_status_field("key_mgmt") != "WPA-PSK":
        raise Exception("Unexpected key_mgmt(1)")
    if dev[0].get_status_field("pairwise_cipher") != "TKIP":
        raise Exception("Unexpected pairwise(1)")
    if dev[1].get_status_field("key_mgmt") != "WPA2-EAP-SHA256":
        raise Exception("Unexpected key_mgmt(2)")
    if dev[2].get_status_field("key_mgmt") != "SAE":
        raise Exception("Unexpected key_mgmt(3)")

    hwsim_utils.test_connectivity(dev[0], dev[1])
    hwsim_utils.test_connectivity(dev[1], dev[2])
    hwsim_utils.test_connectivity(dev[0], dev[2])
    for i in range(3):
        hwsim_utils.test_connectivity(dev[i], hapd)
        dev[i].request("DISCONNECT")

    dev[0].connect(ssid, key_mgmt="WPA-PSK WPA-PSK-SHA256", psk=passphrase,
                   scan_freq="2412")
    dev[1].connect(ssid, key_mgmt="WPA-EAP", proto="WPA", eap="GPSK",
                   identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")
    dev[2].connect(ssid, key_mgmt="WPA-PSK WPA-PSK-SHA256 SAE", psk=passphrase,
                   scan_freq="2412")

    if dev[0].get_status_field("key_mgmt") != "WPA2-PSK-SHA256":
        raise Exception("Unexpected key_mgmt(1b)")
    if dev[0].get_status_field("pairwise_cipher") != "CCMP":
        raise Exception("Unexpected pairwise(1b)")
    if dev[1].get_status_field("key_mgmt") != "WPA/IEEE 802.1X/EAP":
        raise Exception("Unexpected key_mgmt(2b)")
    if dev[2].get_status_field("key_mgmt") != "SAE":
        raise Exception("Unexpected key_mgmt(3b)")

    for i in range(3):
        dev[i].request("DISCONNECT")

    dev[0].connect(ssid, key_mgmt="FT-PSK", psk=passphrase, scan_freq="2412")
    dev[1].connect(ssid, key_mgmt="FT-EAP", eap="GPSK", identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412")
    dev[2].connect(ssid, psk=passphrase, key_mgmt="FT-SAE", scan_freq="2412")

    if dev[0].get_status_field("key_mgmt") != "FT-PSK":
        raise Exception("Unexpected key_mgmt(1c)")
    if dev[1].get_status_field("key_mgmt") != "FT-EAP":
        raise Exception("Unexpected key_mgmt(2c)")
    if dev[2].get_status_field("key_mgmt") != "FT-SAE":
        raise Exception("Unexpected key_mgmt(3c)")