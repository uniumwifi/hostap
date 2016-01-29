/*
 * hostapd / Interface steering
 * Copyright (c) 2015 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef STEERING_H
#define STEERING_H

#define MAX_STEERING_TIMESTAMP_FILES 100
/* BANDSTEERING_FRESH_SECONDS is how long we consider a probe timestamp to be
 * fresh (and we do not need to overwrite it). */
#define BANDSTEERING_FRESH_SECONDS 10
/* BANDSTEERING_EXPIRATION_SECONDS is how long, after steering a station, we
 * allow it to connect to the non-target interface. */
#define BANDSTEERING_EXPIRATION_SECONDS 210
/* BANDSTEERING_THRESHOLD_RSSI is the minimum RSSI of the [2.4GHz] assoc request
 * at which we will definitely steer candidate stations. */
#define BANDSTEERING_THRESHOLD_RSSI -45
/* BANDSTEERING_RECENT_SECONDS is the amount of time a probe on the target
 * interface is considered recent. If the assoc request meets the MIN_RSSI
 * and there has been a target probe request in the last RECENT_SECONDS, then
 * we will steer the station. */
#define BANDSTEERING_RECENT_SECONDS 15
/* BANDSTEERING_DEFER_SECONDS is how long we will not steer a station to
 * a given interface. */
#define BANDSTEERING_DEFER_SECONDS 20

extern char *steering_path;
/* steering_rsi_threshold is the minimum RSSI for two things:
 * 1. a probe request if it is to be recorded on an interface
 * 2. the [2.4GHz] assoc request if we are to consider steering the station
 *     We will never steer if the assoc request is weaker than this. */
extern int steering_rsi_threshold;
extern char *steering_target_interface;

struct hostapd_data;
enum hostapd_hw_mode;
struct ieee80211_mgmt;
struct os_reltime;

typedef enum {
  STEER_EVENT_PROBE,
  STEER_EVENT_ATTEMPT,
  STEER_EVENT_FAILED,
  STEER_EVENT_SUCCESSFUL,
  STEER_EVENT_CONNECT,
  STEER_EVENT_DEFER,
  NUM_STEER_EVENTS } steer_event_type;
typedef enum {
  CURRENT_INTERFACE,
  TARGET_INTERFACE,
  NUM_STEERING_PATH_TYPES } steering_interface_type;

/**
 * Initializes infrastructure needed by band steering code. This should be
 * called at startup.
 */
int bandsteer_init();

/**
 * Initializes bandsteering infrastructure related to one particular interface.
 * This should be called after bandsteer_init() but prior to bringing up an
 * AP on the interface.
 *
 * Returns 0 if no error, non-zero if there is any error.
 */
int bandsteer_interface_init(struct hostapd_iface *iface);

/**
 * Writes a probe timestamp for the mac address to request_logging_path if
 * the ssi_signal is strong enough. This indicates both that
 * 1. the station is a candidate to be steered to this frequency band, and
 * 2. the station has a strong enough signal that we may steer it in the near
 *     future.
 * Returns 1 if the write succeeded, 0 otherwise.
 */
int write_probe_timestamp(const struct hostapd_data *hapd,
                          const u8 *mac,
                          int ssi_signal);

/**
 * Writes a connect timestamp for the mac address for this interface's SSID.
 * This indicates that the station has connected on this SSID and we can
 * steer it from now on.
 */
int write_connect_timestamp(const struct hostapd_data *hapd, const u8 *sta_mac);

/**
 * Writes a steering event timestamp for the mac address to prevent steering
 * for a period of time after the device is disconnected.
 */
int write_disconnect_timestamp(const struct hostapd_data *hapd,
                               const u8 *sta_mac);

/**
 * Determine if the given sta_mac should be steered to a different interface.
 * In the process, it records when the station was steered.
 * Return 1 if it shold be steered, 0 otherwise.
 */
int should_steer_on_assoc(const struct hostapd_data *hapd,
                          const u8 *sta_mac, int ssi_signal, int reassoc);

extern int steering_mechanism;

#endif /* STEERING_H */
