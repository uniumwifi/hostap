/*
 * WPA Supplicant - background scan and roaming interface
 * Copyright (c) 2009-2010, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef BGSCAN_I_H
#define BGSCAN_I_H

/*
 * The signal monitoring code is an optional facility for bgscan algorithms
 * that want to track both signal strength and noise floor (e.g. so they can
 * make decisions based on received signal strength relative to noise floor).
 *
 * calc_threshold: Signal strength threshold for generating CQM events.
 *     When signal strength passes above or below this value CQM events
 *     are generated.  rssi_threshold is initialized from user-specified
 *     options to the algorithm and then recalculated based on the current
 *     noise floor.
 * headroom: The the threshold for signal above the noisefloor for
 *     generating CQM events.  headroom is calculated at initialization
 *     from the user-specified signal strength and then used to calculate
 *     calc_threshold using the current noise floor.
 * hysteresis: Hysterisis value passed into the driver CQM to indicate
 *     how large a delta in received signal (in dBm) from the last CQM
 *     event should trigger another CQM event.
 */
struct bgscan_signal_monitor_state {
	struct wpa_supplicant *wpa_s;
	int calc_threshold;
	int headroom;
	int hysteresis;
};

void bgscan_init_signal_monitor(struct bgscan_signal_monitor_state *sm_state,
				struct wpa_supplicant *wpa_s,
				int signal_threshold,
				int hysteresis);
void bgscan_deinit_signal_monitor(struct bgscan_signal_monitor_state *sm_state);
void bgscan_update_signal_monitor(struct bgscan_signal_monitor_state *sm_state,
				  int current_signal, int current_noise);
int bgscan_poll_signal_monitor(struct bgscan_signal_monitor_state *sm_state,
			       struct wpa_signal_info *siginfo_ret);


/*
 * The time (secs) to delay updates to the CQM monitoring parameters.  This is
 * done to collapse rapid changes into a single request.
 */
#define BGSCAN_NOISEFLOOR_UPDATE_DELAY 10

/*
 * The starting/default noise floor for the channel (dBm).  This also
 * serves as the reference noise floor for user-specified signal strength
 * values in bgscan algorithms that use these facilities.
 */
#define BGSCAN_DEFAULT_NOISE_FLOOR -95

/*
 * Range [+/-] for determining if the noise floor has changed enough for
 * us to adjust the RSSI threshold.
 */
#define BGSCAN_NOISEFLOOR_TOLERANCE 1
#endif /* BGSCAN_I_H */
