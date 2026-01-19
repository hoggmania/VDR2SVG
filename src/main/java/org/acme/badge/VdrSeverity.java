package org.acme.badge;

import java.util.Locale;

enum VdrSeverity {
    CRITICAL(4),
    HIGH(3),
    MEDIUM(2),
    LOW(1),
    UNASSIGNED(0);

    private final int rank;

    VdrSeverity(int rank) {
        this.rank = rank;
    }

    int rank() {
        return rank;
    }

    boolean isMoreSevereThan(VdrSeverity other) {
        return this.rank > other.rank;
    }

    static VdrSeverity fromString(String value) {
        if (value == null) {
            return UNASSIGNED;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "critical" -> CRITICAL;
            case "high" -> HIGH;
            case "medium", "moderate" -> MEDIUM;
            case "low" -> LOW;
            case "info", "informational", "none", "unknown", "unassigned", "" -> UNASSIGNED;
            default -> UNASSIGNED;
        };
    }
}
