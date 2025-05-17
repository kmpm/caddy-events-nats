// SPDX-FileCopyrightText: 2025 Peter Magnusson
//
// SPDX-License-Identifier: Apache-2.0

package caddynats

func isTrue(s string) bool {
	if s == "yes" || s == "on" || s == "true" || s == "1" {
		return true
	}
	return false
}
