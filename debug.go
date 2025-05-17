// SPDX-FileCopyrightText: 2025 Peter Magnusson <me@kmpm.se>
//
// SPDX-License-Identifier: Apache-2.0
//go:build caddyevents_debug

package caddynats

func init() {
	// This is a debug build, so we can enable debug logging
	// or any other debug-specific functionality here.
	// For example, we could set a global debug flag or
	// initialize a debug logger.
	debugMode = true
}
