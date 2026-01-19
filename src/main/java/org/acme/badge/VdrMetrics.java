package org.acme.badge;

record VdrMetrics(int critical, int high, int medium, int low, int unassigned, boolean metricsAvailable) {
    static VdrMetrics noMetrics() {
        return new VdrMetrics(0, 0, 0, 0, 0, false);
    }

    static VdrMetrics withCounts(int critical, int high, int medium, int low, int unassigned) {
        return new VdrMetrics(critical, high, medium, low, unassigned, true);
    }

    int total() {
        return critical + high + medium + low + unassigned;
    }
}
