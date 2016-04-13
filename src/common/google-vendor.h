/*
 * Copyright (c) 2016 Google, Inc.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef GOOGLE_VENDOR_H
#define GOOGLE_VENDOR_H

#include <utils/common.h>

/*
 * This file defines some of the attributes used along with Google OUI
 * f4:f5:e8.
 */

#define OUI_GOOGLE 0xF4F5E8 /* Google */

#define VENDOR_GOOGLE_DEBUG_DIALOG_TOKEN_TYPE	0x02

/*
 * GOogle Debug Dialog Token Information Element
 */
struct google_debug_dialog_token_ie {
	/* Element ID: 221 (0xdd); Length: 8 */
	/* required fields for debug dialog token */
	u8 oui[3]; /* f4:f5:e8 */
	u8 oui_type; /* 1 */
	le32 dialog_token;
} STRUCT_PACKED;

#endif /* GOOGLE_VENDOR_H */
