/*
 * hostapd / Interface steering
 * Copyright (c) 2015 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include "common.h"
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "hostapd.h"
#include "steering.h"

#define BANDSTEER_DIR_MODE S_IRWXU

/* Creates the directory if it doesn't already exist.
 * Returns 0 if the directory already exists or it was created.
 * It does not attempt to create the parent directory.
 */
static int ensure_dir_exists(const char *path, mode_t mode) {
	int rc;
	rc = mkdir(path, mode);
	if ((rc == -1) && (errno == EEXIST)) {
		rc = 0;
	}
	return rc;
}

/**
 * Returns the interface name used for steering this BSS.  This corresponds to
 * the name of the first BSS on the interface.
 */
static char *steering_interface_name(const struct hostapd_data *hapd) {
	return hapd->iface->bss[0]->conf->iface;
}

/**
 * Convert the ssid into a string that is usable in a filename. The resulting
 * string must be unique. Since SSIDs are user defined, they are a potential
 * attack vector into the system. So, their encoding cannot be misinterpreted
 * as any other filename. In other words, we cannot allow ssid encodings
 * like '../bin' or '/' as trying to access such files by name could cause
 * problems.
 *
 * The resulting ssid_string is null terminated.
 *
 * Returns the length of the resulting ssid string. Note that if the buffer
 * is not large enough, then it will be filled with as many characters as
 * will fit.
 */
static int ssid_to_str(char *buf, size_t buf_size,
                       const u8 *ssid, size_t ssid_len) {
	int i, j;
	char add_char;
	u8 bits;
	if (buf_size == 0) {
		return 0;
	}

	j = 0;
	for (i = 0; i < ssid_len; i++) {
		if (isalnum(ssid[i]) || (ssid[i] != 0x0 && os_strchr("_- ", ssid[i]))) {
			if (ssid[i] == ' ') {
				add_char = '+';
			} else {
				add_char = ssid[i];
			}
			if (j >= buf_size - 1) {
				break;
			}
			buf[j++] = add_char;
		} else {
			/* Encode the 8 bit value */
			char alnum_chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
			if (j >= buf_size - 3) {
				break;
			}
			bits = (ssid[i] >> 4) & 0xF;
			buf[j++] = '=';
			buf[j++] = alnum_chars[bits];
			bits = ssid[i] & 0xF;
			buf[j++] = alnum_chars[bits];
		}
	}

	buf[j] = '\0';
	return j;
}

/**
 * Returns the filename-safe name used for SSID timestamps for this BSS.  Note
 * that the value returned is in a static variable, so it is valid only until
 * this function is called again.
 */
static char *steering_ssid_name(const struct hostapd_data *hapd,
                                char *buf, size_t buf_size) {
	ssid_to_str(buf, buf_size,
	            hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
	return buf;
}

/**
 * Gets the appropriate timestamp directory path and puts it into buf.
 * It returns the number of characters written.
 *
 * hapd: struct representing this particular BSS.
 * steer_event: actual type of the event (e.g. STEER_EVENT_PROBE,
 *    STEER_EVENT_ATTEMPT, STEER_EVENT_CONNECT).
 *    If steer_event is STEER_EVENT_CONNECT, then the timestamp directory is
 *    chosen based upon the SSID for this interface (the interface type
 *    does not matter in this case).
 * interface_type: whether to use the CURRENT_INTERFACE (i.e. hapd) or the
 *    steering TARGET_INTERFACE for interface-based timestamps (all but
 *    LOG_CONNECT).
 */
static int get_timestamp_dir(const struct hostapd_data *hapd,
                             steer_event_type steer_event,
                             steering_interface_type interface_type,
                             char *buf,
                             size_t buf_size) {
	if (steering_path == NULL) {
		return 0;
	}

	int pos;
	pos = os_strlcpy(buf, steering_path, buf_size);
	pos += os_strlcpy(&buf[pos], "/", buf_size - pos);

	char *subdir;
	if (steer_event == STEER_EVENT_CONNECT) {
		pos += os_strlcpy(&buf[pos], "s_", buf_size - pos);
		pos += ssid_to_str(&buf[pos], buf_size - pos,
		                   hapd->conf->ssid.ssid,
		                   hapd->conf->ssid.ssid_len);
	} else if (interface_type == TARGET_INTERFACE) {
		pos += os_strlcpy(&buf[pos], "i_", buf_size - pos);
		pos += os_strlcpy(&buf[pos], steering_target_interface,
		                  buf_size - pos);
	} else {
		pos += os_strlcpy(&buf[pos], "i_", buf_size - pos);
		pos += os_strlcpy(&buf[pos], steering_interface_name(hapd),
		                  buf_size - pos);
	}
	return pos;
}

static int get_timestamp_filename(const u8 *mac,
                                  const struct hostapd_data *hapd,
                                  steer_event_type steer_event,
                                  steering_interface_type interface_type,
                                  char *buf, size_t buf_size) {
	int pos;
	if (steering_path == NULL) {
		return 0;
	}

	pos = get_timestamp_dir(hapd, steer_event, interface_type, buf,
	                        buf_size);
	if (os_snprintf(&buf[pos], buf_size - pos, "/" COMPACT_MACSTR ".%d",
	                MAC2STR(mac), steer_event) < 0) {
		wpa_printf(MSG_ERROR, "os_snprintf couldn't format filename: %s",
		           strerror(errno));
		return 0;
	}

	return 1;
}


int bandsteer_init() {
	char mkpath[256];
	char *p;
	int rc = 0;

	if (!steering_path) {
		hostapd_logger(NULL, NULL, HOSTAPD_MODULE_IEEE80211,
		                 HOSTAPD_LEVEL_INFO, "Steering disabled");
		return 0;
	}

	hostapd_logger(NULL, NULL, HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
	               "Steering enabled: target=%s, dir=%s",
	               steering_target_interface, steering_path);

	if (steering_path[0] != '/') {
		wpa_printf(MSG_ERROR,
		           "Band steering path (%s) is not absolute.",
		           steering_path);
		return -1;
	}

	os_strlcpy(mkpath, steering_path, sizeof(mkpath));
	mkpath[sizeof(mkpath) - 1] = '\0';
	for (p=&mkpath[1]; p && !rc; ) {
		if (*p == '\0') {
			/* No more subdirectories to check/create */
			return 0;
		}
		if (*p == '/') {
			/* Consecutive slashes in pathname */
			return -1;
		}
		p = strchr(p, '/');
		if (!p) {
			/* This is the last subdirectory component */
			return ensure_dir_exists(mkpath, BANDSTEER_DIR_MODE);
		}
		*p = '\0';
		rc = ensure_dir_exists(mkpath, BANDSTEER_DIR_MODE);
		*p = '/';
		p++;
	}
	return rc;
}

/**
 * Initializes steering data structures needed for a particular ssid.
 * Returns 0 on success.
 */
static int bandsteer_ssid_init(struct hostapd_data *hapd) {
	char mkpath[256];
	if (!steering_path) {
		return 0;
	}
	get_timestamp_dir(hapd, STEER_EVENT_CONNECT, CURRENT_INTERFACE,
	                  mkpath, sizeof(mkpath));
	wpa_printf(MSG_INFO, "bandsteer_bss_init - %s", mkpath);
	return ensure_dir_exists(mkpath, BANDSTEER_DIR_MODE);
}

int bandsteer_interface_init(struct hostapd_iface *iface) {
	char mkpath[256];
	int k;
	int rc;
	if (!steering_path) {
		return 0;
	}
	get_timestamp_dir(iface->bss[0], STEER_EVENT_PROBE, CURRENT_INTERFACE,
	                  mkpath, sizeof(mkpath));
	wpa_printf(MSG_INFO, "bandsteer_interface_init - %s", mkpath);
	rc = ensure_dir_exists(mkpath, BANDSTEER_DIR_MODE);
	if (rc) {
		return rc;
	}

	/* Ensure that timestamp directories exist for each SSID */
	for (k = 0; k < iface->num_bss; k++) {
		rc = bandsteer_ssid_init(iface->bss[k]);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

static int should_garbage_collect(const struct dirent *name, int type) {
	char *extension = os_strrchr(name->d_name, '.');
	char buf[4];
	os_snprintf(buf, sizeof(buf), ".%d", type);

	return os_strncmp(extension, buf, sizeof(buf)) == 0;
}

static int is_probe_timestamp(const struct dirent *name) {
	return should_garbage_collect(name, STEER_EVENT_PROBE);
}

static int is_attempt_timestamp(const struct dirent *name) {
	return should_garbage_collect(name, STEER_EVENT_ATTEMPT);
}

static int is_failed_timestamp(const struct dirent *name) {
	return should_garbage_collect(name, STEER_EVENT_FAILED);
}

static int is_connect_timestamp(const struct dirent *name) {
	return should_garbage_collect(name, STEER_EVENT_CONNECT);
}

static int is_defer_timestamp(const struct dirent *name) {
	return should_garbage_collect(name, STEER_EVENT_DEFER);
}

static int file_ctime_lt(const struct dirent **a, const struct dirent **b) {
	struct stat astat, bstat;

	/* If we can't stat both of the files, give up and say they're equivalent. */
	if (stat((*a)->d_name, &astat) == -1 || stat((*b)->d_name, &bstat) == -1) {
		return 0;
	}

	return astat.st_ctime - bstat.st_ctime;
}

/**
 * Delete all but the most recent MAX_TIMESTAMP_FILES files of the
 * given type for the BSS represented by hapd.
 * Returns the number of files deleted.
 */
static int garbage_collect_timestamp_files(
		const struct hostapd_data *hapd,
		steer_event_type steer_event) {
	int num_timestamp_files = 0, num_timestamp_files_deleted = 0, i = 0;
	struct dirent **namelist;
	char original_cwd[1024];
	char timestamp_dir[1024];
	char *filename;
	int error = 0;
	int (*timestamp_filter)(const struct dirent *) = NULL;

	if (getcwd(original_cwd, sizeof(original_cwd)) == NULL) {
		wpa_printf(MSG_ERROR, "getcwd(): %s", strerror(errno));
		return -1;
	}

	get_timestamp_dir(hapd, steer_event, CURRENT_INTERFACE,
	                  timestamp_dir, sizeof(timestamp_dir));

	if (chdir(timestamp_dir) == -1) {
		wpa_printf(MSG_ERROR, "chdir(%s): %s",
		           timestamp_dir, strerror(errno));
		return -1;
	}

	switch(steer_event) {
	case STEER_EVENT_PROBE:
		timestamp_filter = is_probe_timestamp;
		break;
	case STEER_EVENT_ATTEMPT:
		timestamp_filter = is_attempt_timestamp;
		break;
	case STEER_EVENT_FAILED:
		timestamp_filter = is_failed_timestamp;
		break;
	case STEER_EVENT_CONNECT:
		timestamp_filter = is_connect_timestamp;
		break;
	case STEER_EVENT_DEFER:
		timestamp_filter = is_defer_timestamp;
		break;
	}

	num_timestamp_files = scandir(timestamp_dir, &namelist,
	                              timestamp_filter, file_ctime_lt);
	/* TODO(walker): Remove eligible timestamps (like DEFER)
	 * when they have expired. */
	for (i = 0; i < num_timestamp_files; ++i) {
		/* TODO(walker): Check the below "-2" comment. With the filter
		 * function, I do not believe "." and ".." are included. */
		if (MAX_STEERING_TIMESTAMP_FILES <
		    /* The -2 is because scandir includes "." and "..". */
		    (num_timestamp_files - 2) - num_timestamp_files_deleted) {
			filename = namelist[i]->d_name;
			if (filename[0] != '.' && !error) {
				if (unlink(filename) == -1) {
					wpa_printf(MSG_ERROR, "unlink(%s): %s", filename, strerror(errno));
					error = 1;
				} else {
					++num_timestamp_files_deleted;
				}
			}
		}
		os_free(namelist[i]);
 	}
	os_free(namelist);

	if (chdir(original_cwd) == -1) {
		wpa_printf(MSG_ERROR, "chdir(%s): %s", original_cwd, strerror(errno));
		return -1;
 	}

	return error ? -1 : num_timestamp_files_deleted;
}

/**
 * Reads a timestamp from either request_logging_path or steering_timestamp_path
 * (based on path) for the source address in mgmt, putting the result in
 * timestamp.  Returns 1 if the read succeeded, 0 otherwise.
 */
static int read_timestamp(const struct hostapd_data *hapd,
                          const u8 *mac,
                          steer_event_type steer_event,
                          steering_interface_type interface_type,
                          struct os_reltime *timestamp) {
	FILE *f;
	char filename[1024];
	int success = 1;
	struct stat st;
	os_time_t sec = 0, usec = 0;

	if (!get_timestamp_filename(mac, hapd, steer_event, interface_type,
	                            filename, sizeof(filename))) {
		return 0;
	}

	if (stat(filename, &st) == -1) {
		return 0;
	}

	f = fopen(filename, "r");
	if (f == NULL) {
		wpa_printf(MSG_ERROR, "open(%s) for read: %s", filename, strerror(errno));
		return 0;
	}

	if (timestamp) {
		if (fscanf(f, "%d %d", &timestamp->sec, &timestamp->usec) != 2) {
			wpa_printf(MSG_ERROR, "fscanf from %s: %s", filename, strerror(errno));
			success = 0;
		}
	}

	if (fclose(f) == EOF) {
		wpa_printf(MSG_ERROR, "fclose(%s): %s", filename, strerror(errno));
		return 0;
	}

	return success;
}

/**
 * Writes timestamp for the source address in mgmt to request_logging_path.
 * Also garbage collects timestamps.
 * Returns 1 if the write succeeded, 0 otherwise.
 */
static int write_timestamp(const struct hostapd_data *hapd,
                           const u8 *mac,
                           steer_event_type steer_event,
                           const struct os_reltime *timestamp) {
	FILE *f;
	char filename[1024], tmp_filename[1024];
	int success = 0;

	if (garbage_collect_timestamp_files(hapd, steer_event) == -1) {
		wpa_printf(MSG_ERROR,
		           "Garbage collecting steering timestamp files failed: %s",
		           strerror(errno));
		return 0;
	}

	if (!get_timestamp_filename(mac, hapd, steer_event, CURRENT_INTERFACE,
	                            filename, sizeof(filename))) {
		return 0;
	}

	/* Create a temporary filename to prevent multiple interfaces on the
	 * same band from touching each others' writes.
	 */
	if (os_snprintf(tmp_filename, sizeof(tmp_filename), "%s%s", filename,
	                os_strrchr(hapd->iface->config_fname, '.')) < 0) {
		wpa_printf(MSG_ERROR, "os_snprintf couldn't format temp filename: %s",
		           strerror(errno));
		return 0;
	}

	if ((f = fopen(tmp_filename, "w")) == NULL) {
		wpa_printf(MSG_ERROR, "fopen(%s) for write: %s", tmp_filename,
		           strerror(errno));
		return 0;
	}

	if (timestamp) {
		if (fprintf(f, "%d %d", timestamp->sec, timestamp->usec) < 0) {
			wpa_printf(MSG_ERROR, "fprintf to %s: %s", tmp_filename, strerror(errno));
		} else {
			success = 1;
		}
	}

	if (fclose(f) == EOF) {
		wpa_printf(MSG_ERROR, "fclose(%s): %s", tmp_filename, strerror(errno));
		return 0;
	}

	if (rename(tmp_filename, filename) != 0) {
		wpa_printf(MSG_ERROR, "rename(%s, %s): %s", tmp_filename, filename,
		           strerror(errno));
		return 0;
	}

	wpa_printf(MSG_INFO, "Set timestamp for " MACSTR
	           " (iface=%s/%s, event=%d)",
	           MAC2STR(mac), steering_interface_name(hapd),
	           hapd->conf->iface, steer_event);
	return success;
}

/**
 * Calls write_timestamp_file unless there is an existing timestamp younger than
 * BANDSTEERING_EXPIRATION_SECONDS.
 * Returns 0 on write or garbage collection failure, 1 otherwise.
 */
static int maybe_write_timestamp(const struct hostapd_data *hapd,
                                 const u8 *mac,
                                 steer_event_type steer_event,
                                 const struct os_reltime *timestamp) {
	struct os_reltime now, prev_timestamp;

	os_get_reltime(&now);
	if (!read_timestamp(hapd, mac, steer_event, CURRENT_INTERFACE,
	                    &prev_timestamp) ||
	    os_reltime_expired(&now, &prev_timestamp,
	                       BANDSTEERING_FRESH_SECONDS)) {
		if (!write_timestamp(hapd, mac, steer_event, timestamp)) {
			wpa_printf(MSG_ERROR, "Failed to write timestamp file.");
			return 0;
		}
	}
	return 1;
}

int write_probe_timestamp(const struct hostapd_data *hapd,
                          const u8 *mac,
                          int ssi_signal) {
	struct os_reltime now;
	if (!steering_path || (ssi_signal < steering_rsi_threshold)) {
		return 0;
	}

	os_get_reltime(&now);
	maybe_write_timestamp(hapd, mac, STEER_EVENT_PROBE, &now);
	return 0;
}

int write_connect_timestamp(const struct hostapd_data *hapd,
                            const u8 *sta_mac) {
	struct os_reltime now;
	os_get_reltime(&now);
	write_timestamp(hapd, sta_mac, STEER_EVENT_CONNECT, &now);
	return 0;
}

int write_disconnect_timestamp(const struct hostapd_data *hapd,
                               const u8 *sta_mac) {
	struct os_reltime now;
	os_get_reltime(&now);
	/* TODO(walker): Reduce the number of extraneous timestamps by only
	 * writing the timestamp for the target interface (but that assumes
	 * the algorithm can never steer in multiple directions). Better
	 * would just be to clean up expired timestamps when garbage
	 * collecting. */
	write_timestamp(hapd, sta_mac, STEER_EVENT_DEFER, &now);
	return 0;
}

/*
 * To be called upon receiving an ASSOC request. Returns 1 if the sta with
 * |mac| should be steered, 0 otherwise.
 */
int should_steer_on_assoc(const struct hostapd_data *hapd,
                          const u8 *sta_mac, int ssi_signal, int reassoc) {
	struct os_reltime now, probe_time, bandsteer_time, probe_delta_time,
            steer_delta_time, defer_time;
	int have_timestamp;
	char *steering_name;
        char buf[128];
	if (steering_target_interface == NULL) {
		return FALSE;
	}
	steering_name = steering_interface_name(hapd);
	if (!strcmp(steering_target_interface, steering_name)) {
		hostapd_logger(hapd->msg_ctx, sta_mac,
		               HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
		               "Assoc on steering target (%s); rssi=%d",
		               steering_name, ssi_signal);
		wpa_msg(hapd->msg_ctx, MSG_INFO,
		               AP_STA_NO_STEERING MACSTR " target-interface %d",
		               MAC2STR(sta_mac), ssi_signal);
		return FALSE;
	}
	/* Steering is enabled and this is not the target interface. */

	if (reassoc) {
		hostapd_logger(hapd->msg_ctx, sta_mac,
		               HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
		               "Assoc no steer - reassoc; rssi=%d",
		               ssi_signal);
		wpa_msg(hapd->msg_ctx, MSG_INFO,
		               AP_STA_NO_STEERING MACSTR " reassoc %d",
		               MAC2STR(sta_mac), ssi_signal);
		return FALSE;
	}

	/* Check that this station has previously connected on this SSID */
	if (!read_timestamp(hapd, sta_mac, STEER_EVENT_CONNECT,
	                    CURRENT_INTERFACE, NULL)) {
		hostapd_logger(hapd->msg_ctx, sta_mac,
		               HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
		               "Assoc no steer - new station (%s); rssi=%d "
		               "ssid=%s",
		               steering_name, ssi_signal,
		               steering_ssid_name(hapd, buf, sizeof(buf)));
		wpa_msg(hapd->msg_ctx, MSG_INFO,
		               AP_STA_NO_STEERING MACSTR " new-station %d",
		               MAC2STR(sta_mac), ssi_signal);
		return FALSE;
        }

	os_get_reltime(&now);

	/* Do not steer if steering is currently deferred to the target */
	/* TODO(walker): Probably more correct to store the actual expiration
	 * in the timestamp, but that requires more complicated logic when
	 * writing the timestamp, requiring that we write
	 * max(current expiration, desired expiration) instead of just
	 * overwriting the timestamp like we do now. For current code meets
	 * our immediate needs. */
	if (read_timestamp(hapd, sta_mac, STEER_EVENT_DEFER, TARGET_INTERFACE,
	                   &defer_time) &&
	    !os_reltime_expired(&now, &defer_time, BANDSTEERING_DEFER_SECONDS)) {
		hostapd_logger(hapd->msg_ctx, sta_mac,
		               HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
		               "Assoc no steer - deferred; rssi=%d",
		               ssi_signal);
		wpa_msg(hapd->msg_ctx, MSG_INFO,
		               AP_STA_NO_STEERING MACSTR " deferred %d",
		               MAC2STR(sta_mac), ssi_signal);
		return FALSE;
	}

	if (!read_timestamp(hapd, sta_mac, STEER_EVENT_PROBE, TARGET_INTERFACE,
	                    &probe_time)) {
		hostapd_logger(hapd->msg_ctx, sta_mac,
		               HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
		               "Assoc no steer - non-candidate; rssi=%d",
                               ssi_signal);
		wpa_msg(hapd->msg_ctx, MSG_INFO,
		               AP_STA_NO_STEERING MACSTR " non-candidate %d",
		               MAC2STR(sta_mac), ssi_signal);
		return FALSE;
	}

	/* We do not want to steer a station if its signal strength indicates
	 * it is not a candidate NOW.
	 * If the assoc signal strength is weak
	 * (rssi < steering_rsi_threshold [dflt=-60]), then we will not steer.
	 * If the assoc signal strength is not strong
	 * (rssi < BANDSTEERING_THRESHOLD_RSSI [-45]) and we have not
	 * recently (within BANDSTEERING_RECENT_SECONDS [15]) received a
	 * probe request on the target interface, then we also will not
	 * steer. */
	os_reltime_sub(&now, &probe_time, &probe_delta_time);
	if ((ssi_signal < steering_rsi_threshold) ||
            ((os_reltime_expired(&now, &probe_time,
	                       BANDSTEERING_RECENT_SECONDS) &&
              (ssi_signal < BANDSTEERING_THRESHOLD_RSSI)))) {
		hostapd_logger(hapd->msg_ctx, sta_mac,
		               HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
		               "Assoc no steer - weak signal; "
		               "rssi=%d probe_delta_t=%d.%02d",
		               ssi_signal, probe_delta_time.sec,
		               probe_delta_time.usec / 10000);
		wpa_msg(hapd->msg_ctx, MSG_INFO,
		               AP_STA_NO_STEERING MACSTR " weak-signal %d",
		               MAC2STR(sta_mac), ssi_signal);
		return FALSE;
	}

	/* Steer station if it has never been steered or if it hasn't been
	 * steered recently. */
	have_timestamp = read_timestamp(hapd, sta_mac, STEER_EVENT_ATTEMPT,
	                                CURRENT_INTERFACE, &bandsteer_time);
	if (!have_timestamp ||
	    os_reltime_expired(&now, &bandsteer_time,
	                       BANDSTEERING_EXPIRATION_SECONDS)) {
		write_timestamp(hapd, sta_mac, STEER_EVENT_ATTEMPT, &now);
		if (!have_timestamp) {
			steer_delta_time.sec = 0;
			steer_delta_time.usec = 0;
		} else {
			os_reltime_sub(&now, &bandsteer_time, &steer_delta_time);
		}
		hostapd_logger(hapd->msg_ctx, sta_mac,
		               HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
		               "Assoc steer; rssi=%d steer_delta_t=%d.%02d "
		               "probe_delta_t=%d.%02d",
		               ssi_signal, steer_delta_time.sec,
		               steer_delta_time.usec / 10000,
		               probe_delta_time.sec,
		               probe_delta_time.usec / 10000);
		wpa_msg(hapd->msg_ctx, MSG_INFO,
		               AP_STA_STEERING MACSTR " %d",
		               MAC2STR(sta_mac), ssi_signal);
		return TRUE;
	}

	write_timestamp(hapd, sta_mac, STEER_EVENT_FAILED, &now);
	os_reltime_sub(&now, &bandsteer_time, &steer_delta_time);
	hostapd_logger(hapd->msg_ctx, sta_mac,
	               HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
	               "Assoc steer fail; steer_delta_t=%d.%02d rssi=%d",
	               steer_delta_time.sec, steer_delta_time.usec / 10000,
	               ssi_signal);
	wpa_printf(MSG_INFO, "Bandsteering failed for "
	           MACSTR ", associating on %s/%s",
	           MAC2STR(sta_mac), steering_name, hapd->conf->iface);
	return FALSE;
}
