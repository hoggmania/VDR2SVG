package org.acme.badge;

import java.util.Locale;

enum VdrPolicyViolationLevel {
    FAIL,
    WARN,
    INFO,
    NONE;

    static VdrPolicyViolationLevel fromString(String value) {
        if (value == null) {
            return NONE;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "fail", "failed", "failure", "error", "deny", "denied" -> FAIL;
            case "warn", "warning" -> WARN;
            case "info", "informational" -> INFO;
            case "none", "pass", "passed", "ok", "false", "0", "no", "" -> NONE;
            default -> NONE;
        };
    }
}
