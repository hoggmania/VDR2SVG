package org.acme.badge;

record VdrViolationMetrics(int fail, int warn, int info, boolean metricsAvailable) {
    static VdrViolationMetrics noMetrics() {
        return new VdrViolationMetrics(0, 0, 0, false);
    }

    static VdrViolationMetrics withCounts(int fail, int warn, int info) {
        return new VdrViolationMetrics(fail, warn, info, true);
    }

    int total() {
        return fail + warn + info;
    }
}
