package org.acme.badge;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@ApplicationScoped
class VdrBadgeLinkService {
    private final Optional<String> baseUrl;

    VdrBadgeLinkService(@ConfigProperty(name = "vdr.badge.base-url") Optional<String> baseUrl) {
        this.baseUrl = baseUrl;
    }

    String resolveHref(JsonNode vdr, String explicitHref) {
        if (explicitHref != null && !explicitHref.isBlank()) {
            return explicitHref;
        }

        String base = baseUrl.map(String::trim).orElse(null);
        if (base == null || base.isBlank()) {
            return null;
        }

        String name = extractComponentValue(vdr, "name");
        String version = extractComponentValue(vdr, "version");
        if (name == null || version == null) {
            return null;
        }

        String normalizedBase = trimTrailingSlashes(base);
        return normalizedBase + "/" + encodePathSegment(name) + "/" + encodePathSegment(version);
    }

    private String extractComponentValue(JsonNode vdr, String field) {
        if (vdr == null || vdr.isMissingNode() || vdr.isNull()) {
            return null;
        }
        JsonNode value = vdr.path("metadata").path("component").path(field);
        if (value.isMissingNode() || value.isNull()) {
            return null;
        }
        String text = value.asText();
        if (text == null || text.isBlank()) {
            return null;
        }
        return text;
    }

    private String trimTrailingSlashes(String base) {
        int end = base.length();
        while (end > 0 && base.charAt(end - 1) == '/') {
            end--;
        }
        return base.substring(0, end);
    }

    private String encodePathSegment(String value) {
        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8);
        return encoded.replace("+", "%20");
    }
}
