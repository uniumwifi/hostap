/*
 * WPA Supplicant - background scan and roaming module: simple
 * Copyright (c) 2009-2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "drivers/driver.h"
#include "config_ssid.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "scan.h"
#include "bgscan.h"
#include "bgscan_i.h"

struct bgscan_simple_data {
	struct wpa_supplicant *wpa_s;
	const struct wpa_ssid *ssid;
	int scan_interval;
	int signal_threshold;
	int short_scan_count; /* counter for scans using short scan interval */
	int max_short_scans; /* maximum times we short-scan before back-off */
	int short_interval; /* use if signal < threshold */
	int long_interval; /* use if signal > threshold */
	struct os_reltime last_bgscan;
	int *supp_freqs;
	int n_supp_freqs;
	int *scan_freqs;
	int freq_idx;
	struct bgscan_signal_monitor_state signal_monitor;
};


static int * bgscan_simple_get_freqs(struct bgscan_simple_data *data)
{
	int *freqs = data->scan_freqs;
	int i, j;

	if (data->supp_freqs == NULL)
		return NULL;

	if (freqs == NULL)
		return NULL;

	j = 0;
	for (i = data->freq_idx; i < data->n_supp_freqs; i++)
		freqs[j++] = data->supp_freqs[i];
	for (i = 0; i < data->freq_idx; i++)
		freqs[j++] = data->supp_freqs[i];
	freqs[j] = 0;		/* NB: terminator expected elsewhere */

	return freqs;
}


static void log_freqs(const char *tag, const int freqs[])
{
	char msg[1000], *pos;
	int i;

	msg[0] = '\0';
	pos = msg;
	for (i = 0; freqs[i] != 0; i++) {
		int ret;
		ret = os_snprintf(pos, msg + sizeof(msg) - pos, " %d",
				  freqs[i]);
		if (ret < 0 || ret >= msg + sizeof(msg) - pos)
			break;
		pos += ret;
	}
	pos[0] = '\0';
	wpa_printf(MSG_DEBUG, "bgscan simple: %s frequencies:%s", tag, msg);
}


static void bgscan_simple_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct bgscan_simple_data *data = eloop_ctx;
	struct wpa_supplicant *wpa_s = data->wpa_s;
	struct wpa_driver_scan_params params;

	os_memset(&params, 0, sizeof(params));
	params.num_ssids = 1;
	params.ssids[0].ssid = data->ssid->ssid;
	params.ssids[0].ssid_len = data->ssid->ssid_len;

	if (data->ssid->scan_freq == NULL)
		params.freqs = bgscan_simple_get_freqs(data);
	else
		params.freqs = data->ssid->scan_freq;

	/*
	 * If we might be roaming don't let our bgscan be aborted by
	 * outbound traffic.  Otherwise it's ok; this is low priority work.
	 */
	params.low_priority = !wpa_supplicant_need_scan_results(wpa_s);

	wpa_printf(MSG_DEBUG, "bgscan simple: Request a background scan");
	if (params.freqs != NULL)
		log_freqs("Scanning", params.freqs);
	if (wpa_supplicant_trigger_scan(wpa_s, &params)) {
		wpa_printf(MSG_DEBUG, "bgscan simple: Failed to trigger scan");
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_simple_timeout, data, NULL);
	} else {
		if (data->scan_interval == data->short_interval) {
			data->short_scan_count++;
			/*
			 * Spend at most the duration of a long scan interval
			 * scanning at the short scan interval. After that,
			 * revert to the long scan interval.
			 */
			if (data->short_scan_count > data->max_short_scans) {
				data->scan_interval = data->long_interval;
				wpa_printf(MSG_DEBUG, "bgscan simple: Backing "
					   "off to long scan interval");
			}
		} else if (data->short_scan_count > 0) {
			/*
			 * If we lasted a long scan interval without any
			 * CQM triggers, decrease the short-scan count,
			 * which allows 1 more short-scan interval to
			 * occur in the future when CQM triggers.
			 */
			data->short_scan_count--;
		}
		os_get_reltime(&data->last_bgscan);
	}
}


static int bgscan_simple_get_params(struct bgscan_simple_data *data,
				    const char *params)
{
	const char *pos;

	if (params == NULL)
		return 0;

	data->short_interval = atoi(params);

	pos = os_strchr(params, ':');
	if (pos == NULL)
		return 0;
	pos++;
	data->signal_threshold = atoi(pos);
	pos = os_strchr(pos, ':');
	if (pos == NULL) {
		wpa_printf(MSG_ERROR, "bgscan simple: Missing scan interval "
			   "for high signal");
		return -1;
	}
	pos++;
	data->long_interval = atoi(pos);

	return 0;
}


static int in_array(const int *array, int v)
{
	int i;

	if (array == NULL)
		return 0;

	for (i = 0; array[i] != 0; i++)
		if (array[i] == v)
			return 1;
	return 0;
}

static void bgscan_simple_setup_freqs(struct wpa_supplicant *wpa_s,
				      struct bgscan_simple_data *data)
{
	struct hostapd_hw_modes *modes;
	const struct hostapd_hw_modes *infra;
	u16 num_modes, flags;
	int i, j, *freqs;
	size_t count;

	data->supp_freqs = NULL;
	data->freq_idx = 0;

	modes = wpa_drv_get_hw_feature_data(wpa_s, &num_modes, &flags);
	if (!modes)
		return;

	count = 0;
	freqs = NULL;
	for (i = 0; i < num_modes; i++) {
		for (j = 0; j < modes[i].num_channels; j++) {
			int freq, *n;

			if (modes[i].channels[j].flag & HOSTAPD_CHAN_DISABLED)
				continue;
			freq = modes[i].channels[j].freq;
			if (in_array(freqs, freq))	/* NB: de-dup list */
				continue;
			n = os_realloc(freqs, (count + 2) * sizeof(int));
			if (n != NULL) {
				freqs = n;
				freqs[count++] = freq;
				freqs[count] = 0;
			}
		}
		os_free(modes[i].channels);
		os_free(modes[i].rates);
	}
	os_free(modes);

	if (freqs != NULL) {
		/* TODO(sleffler) priority order freqs */
		data->supp_freqs = freqs;
		data->n_supp_freqs = count;
		data->scan_freqs = os_malloc((count + 1) * sizeof(int));

		log_freqs("Supported", freqs);
	}
}


static void * bgscan_simple_init(struct wpa_supplicant *wpa_s,
				 const char *params,
				 const struct wpa_ssid *ssid)
{
	struct bgscan_simple_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->wpa_s = wpa_s;
	data->ssid = ssid;
	if (bgscan_simple_get_params(data, params) < 0) {
		os_free(data);
		return NULL;
	}
	if (data->short_interval <= 0)
		data->short_interval = 30;
	if (data->long_interval <= 0)
		data->long_interval = 30;

	wpa_printf(MSG_DEBUG, "bgscan simple: Signal strength threshold %d  "
		   "Short bgscan interval %d  Long bgscan interval %d",
		   data->signal_threshold, data->short_interval,
		   data->long_interval);

	data->scan_interval = data->short_interval;
	data->max_short_scans = data->long_interval / data->short_interval + 1;
	if (data->signal_threshold) {
		struct wpa_signal_info siginfo;

		bgscan_init_signal_monitor(&data->signal_monitor, wpa_s,
					   data->signal_threshold, 4);

		/* Poll for signal info to set initial scan interval */
		if (bgscan_poll_signal_monitor(&data->signal_monitor,
					       &siginfo) == 0 &&
		    siginfo.current_signal >= data->signal_threshold)
			data->scan_interval = data->long_interval;
	}
	wpa_printf(MSG_DEBUG, "bgscan simple: Init scan interval: %d",
		   data->scan_interval);

	bgscan_simple_setup_freqs(wpa_s, data);

	eloop_register_timeout(data->scan_interval, 0, bgscan_simple_timeout,
			       data, NULL);

	/*
	 * This function is called immediately after an association, so it is
	 * reasonable to assume that a scan was completed recently. This makes
	 * us skip an immediate new scan in cases where the current signal
	 * level is below the bgscan threshold.
	 */
	os_get_reltime(&data->last_bgscan);

	return data;
}


static void bgscan_simple_deinit(void *priv)
{
	struct bgscan_simple_data *data = priv;
	eloop_cancel_timeout(bgscan_simple_timeout, data, NULL);
	if (data->signal_threshold)
		bgscan_deinit_signal_monitor(&data->signal_monitor);
	os_free(data->supp_freqs);
	os_free(data->scan_freqs);
	os_free(data);
}


static int find_freq_index(const struct bgscan_simple_data *data, int freq)
{
	int ix;

	for (ix = data->freq_idx; ix < data->n_supp_freqs; ix++)
		if (freq == data->supp_freqs[ix])
			return ix;
	for (ix = 0; ix < data->freq_idx; ix++)
		if (freq == data->supp_freqs[ix])
			return ix;
	return -1;
}

static int bgscan_simple_notify_scan(void *priv,
				     struct wpa_scan_results *scan_res)
{
	struct bgscan_simple_data *data = priv;

	wpa_printf(MSG_DEBUG, "bgscan simple: scan result notification");

	if (scan_res->aborted && data->supp_freqs != NULL) {
		int last_freq, i, idx;
		/*
		 * Scan was aborted; advance the rotor past known
		 * channels visited.  This does not take into account
		 * channels that were visited but had no scan results.
		 * This should be ok as we always supply a complete
		 * frequency list when we scan.
		 *
		 * NB: can't depend on scan results order matching our
		 * channel list as the upper layers sort results
		 */
		last_freq = 0;
		for (i = 0; i < scan_res->num; i++) {
			if (scan_res->res[i]->freq == last_freq)
				continue;
			last_freq = scan_res->res[i]->freq;
			idx = find_freq_index(data, last_freq) + 1;
			if (idx != -1)
				data->freq_idx = (idx + 1) % data->n_supp_freqs;
		}
	} else
		data->freq_idx = 0;
	wpa_printf(MSG_DEBUG, "bgscan simple: freq_idx %d", data->freq_idx);

	if (data->signal_threshold)
		bgscan_poll_signal_monitor(&data->signal_monitor, NULL);
	eloop_cancel_timeout(bgscan_simple_timeout, data, NULL);
	eloop_register_timeout(data->scan_interval, 0, bgscan_simple_timeout,
			       data, NULL);

	/*
	 * A more advanced bgscan could process scan results internally, select
	 * the BSS and request roam if needed. This sample uses the existing
	 * BSS/ESS selection routine. Change this to return 1 if selection is
	 * done inside the bgscan module.
	 */

	return 0;
}


static void bgscan_simple_notify_beacon_loss(void *priv)
{
	wpa_printf(MSG_DEBUG, "bgscan simple: beacon loss");
	/* TODO: speed up background scanning */
}


static void bgscan_simple_notify_signal_change(void *priv, int above,
					       int current_signal,
					       int current_noise,
					       int current_txrate)
{
	struct bgscan_simple_data *data = priv;
	int scan = 0;
	struct os_reltime now;

	if (data->short_interval == data->long_interval ||
	    data->signal_threshold == 0)
		return;

	wpa_printf(MSG_DEBUG, "bgscan simple: signal level changed "
		   "(above=%d current_signal=%d current_noise=%d "
		   "current_txrate=%d))", above, current_signal,
		   current_noise, current_txrate);

	bgscan_update_signal_monitor(&data->signal_monitor, current_signal,
				     current_noise);

	if (data->scan_interval == data->long_interval && !above) {
		wpa_printf(MSG_DEBUG, "bgscan simple: Start using short "
			   "bgscan interval");
		data->scan_interval = data->short_interval;
		os_get_reltime(&now);
		if (now.sec > data->last_bgscan.sec + 1 &&
		    data->short_scan_count <= data->max_short_scans)
			/*
			 * If we haven't just previously (<1 second ago)
			 * performed a scan, and we haven't depleted our
			 * budget for short-scans, perform a scan
			 * immediately.
			 */
			scan = 1;
		else if (data->last_bgscan.sec + data->long_interval >
			 now.sec + data->scan_interval) {
			/*
			 * Restart scan interval timer if currently scheduled
			 * scan is too far in the future.
			 */
			eloop_cancel_timeout(bgscan_simple_timeout, data,
					     NULL);
			eloop_register_timeout(data->scan_interval, 0,
					       bgscan_simple_timeout, data,
					       NULL);
		}
	} else if (data->scan_interval == data->short_interval && above) {
		wpa_printf(MSG_DEBUG, "bgscan simple: Start using long bgscan "
			   "interval");
		data->scan_interval = data->long_interval;
		eloop_cancel_timeout(bgscan_simple_timeout, data, NULL);
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_simple_timeout, data, NULL);
	} else if (!above) {
		/*
		 * Signal dropped further 4 dB. Request a new scan if we have
		 * not yet scanned in a while.
		 */
		os_get_reltime(&now);
		if (now.sec > data->last_bgscan.sec + 10)
			scan = 1;
	}

	if (scan) {
		wpa_printf(MSG_DEBUG, "bgscan simple: Trigger immediate scan");
		eloop_cancel_timeout(bgscan_simple_timeout, data, NULL);
		eloop_register_timeout(0, 0, bgscan_simple_timeout, data,
				       NULL);
	}
}


const struct bgscan_ops bgscan_simple_ops = {
	.name = "simple",
	.init = bgscan_simple_init,
	.deinit = bgscan_simple_deinit,
	.notify_scan = bgscan_simple_notify_scan,
	.notify_beacon_loss = bgscan_simple_notify_beacon_loss,
	.notify_signal_change = bgscan_simple_notify_signal_change,
};
