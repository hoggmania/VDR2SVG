package org.acme.badge;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Iterator;
import java.util.Locale;
import java.util.Set;

@ApplicationScoped
class VdrMetricsService {
    private static final Set<String> POLICY_VIOLATION_KEYS = Set.of(
            "policyviolation",
            "policyviolationlevel",
            "policyviolationseverity",
            "policyviolationstatus",
            "policyviolationstate",
            "policyviolationtype"
    );
    private static final String[] DIRECT_VIOLATION_FIELDS = {
            "policyViolation",
            "policyViolationLevel",
            "policyViolationSeverity",
            "policyViolationStatus",
            "policyViolationState",
            "policyViolationType"
    };

    VdrMetrics summarize(JsonNode vdr) {
        if (vdr == null || !vdr.isObject()) {
            return VdrMetrics.noMetrics();
        }

        JsonNode vulnerabilities = vdr.path("vulnerabilities");
        if (!vulnerabilities.isArray()) {
            return VdrMetrics.noMetrics();
        }

        if (vulnerabilities.isEmpty()) {
            return VdrMetrics.withCounts(0, 0, 0, 0, 0);
        }

        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;
        int unassigned = 0;

        for (JsonNode vulnerability : vulnerabilities) {
            VdrSeverity severity = resolveSeverity(vulnerability);
            switch (severity) {
                case CRITICAL -> critical++;
                case HIGH -> high++;
                case MEDIUM -> medium++;
                case LOW -> low++;
                case UNASSIGNED -> unassigned++;
            }
        }

        return VdrMetrics.withCounts(critical, high, medium, low, unassigned);
    }

    VdrViolationMetrics summarizePolicyViolations(JsonNode vdr) {
        if (vdr == null || !vdr.isObject()) {
            return VdrViolationMetrics.noMetrics();
        }

        JsonNode vulnerabilities = vdr.path("vulnerabilities");
        if (!vulnerabilities.isArray()) {
            return VdrViolationMetrics.noMetrics();
        }

        int fail = 0;
        int warn = 0;
        int info = 0;
        boolean sawViolation = false;

        for (JsonNode vulnerability : vulnerabilities) {
            String violation = findViolationValue(vulnerability);
            if (violation == null) {
                continue;
            }
            sawViolation = true;
            VdrPolicyViolationLevel level = VdrPolicyViolationLevel.fromString(violation);
            switch (level) {
                case FAIL -> fail++;
                case WARN -> warn++;
                case INFO -> info++;
                case NONE -> {
                }
            }
        }

        if (!sawViolation) {
            return VdrViolationMetrics.noMetrics();
        }

        return VdrViolationMetrics.withCounts(fail, warn, info);
    }

    private VdrSeverity resolveSeverity(JsonNode vulnerability) {
        if (vulnerability == null || vulnerability.isMissingNode() || vulnerability.isNull()) {
            return VdrSeverity.UNASSIGNED;
        }

        JsonNode ratings = vulnerability.path("ratings");
        if (ratings.isArray() && ratings.size() > 0) {
            VdrSeverity highest = VdrSeverity.UNASSIGNED;
            for (JsonNode rating : ratings) {
                VdrSeverity severity = severityFromRating(rating);
                if (severity.isMoreSevereThan(highest)) {
                    highest = severity;
                }
            }
            return highest;
        }

        return VdrSeverity.fromString(asText(vulnerability.path("severity")));
    }

    private VdrSeverity severityFromRating(JsonNode rating) {
        if (rating == null || rating.isMissingNode() || rating.isNull()) {
            return VdrSeverity.UNASSIGNED;
        }
        if (rating.isTextual()) {
            return VdrSeverity.fromString(rating.asText());
        }
        return VdrSeverity.fromString(asText(rating.path("severity")));
    }

    private String findViolationValue(JsonNode vulnerability) {
        if (vulnerability == null || vulnerability.isMissingNode() || vulnerability.isNull()) {
            return null;
        }
        for (String field : DIRECT_VIOLATION_FIELDS) {
            JsonNode value = vulnerability.get(field);
            if (value != null && !value.isNull()) {
                return value.asText();
            }
        }

        JsonNode properties = vulnerability.path("properties");
        return extractViolationValueFromProperties(properties);
    }

    private String extractViolationValueFromProperties(JsonNode properties) {
        if (properties == null || properties.isMissingNode() || properties.isNull()) {
            return null;
        }
        if (properties.isArray()) {
            for (JsonNode property : properties) {
                String name = asText(property.path("name"));
                if (isPolicyViolationPropertyName(name)) {
                    return asText(property.path("value"));
                }
            }
        } else if (properties.isObject()) {
            Iterator<String> fields = properties.fieldNames();
            while (fields.hasNext()) {
                String name = fields.next();
                if (isPolicyViolationPropertyName(name)) {
                    return asText(properties.get(name));
                }
            }
        }
        return null;
    }

    private boolean isPolicyViolationPropertyName(String name) {
        if (name == null) {
            return false;
        }
        String normalized = normalizePropertyName(name);
        return POLICY_VIOLATION_KEYS.contains(normalized);
    }

    private String normalizePropertyName(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        StringBuilder builder = new StringBuilder(lower.length());
        for (int i = 0; i < lower.length(); i++) {
            char value = lower.charAt(i);
            if (Character.isLetterOrDigit(value)) {
                builder.append(value);
            }
        }
        return builder.toString();
    }

    private String asText(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        return node.asText();
    }
}
