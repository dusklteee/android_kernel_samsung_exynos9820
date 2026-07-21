/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PowerShare service-LED indicator bridge for the MAX86915/7 HRM sensor.
 *
 * Wireless PowerShare (reverse charging) reuses the rear HRM LEDs as a
 * status indicator: blue while waiting for a receiver, red while charging
 * one. The Samsung battery driver requests the state via this hook; the
 * HRM sensor driver (max86915.c) implements it on top of its SVC LED path.
 */
#ifndef _LINUX_MAX86915_POWERSHARE_H_
#define _LINUX_MAX86915_POWERSHARE_H_

#include <linux/kconfig.h>

/* Indicator state requested by the battery driver. */
#define PS_LED_OFF		0	/* PowerShare off */
#define PS_LED_STANDBY		1	/* waiting for a receiver -> blue */
#define PS_LED_CHARGING		2	/* charging a receiver    -> red  */

#if IS_ENABLED(CONFIG_MAX86915_POWERSHARE_LED)
int max86915_powershare_led(int state);
#else
static inline int max86915_powershare_led(int state) { return 0; }
#endif

#endif /* _LINUX_MAX86915_POWERSHARE_H_ */
