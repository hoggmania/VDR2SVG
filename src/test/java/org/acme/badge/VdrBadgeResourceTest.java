package org.acme.badge;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class VdrBadgeResourceTest {
    private static final Pattern ROOT_WIDTH_PATTERN = Pattern.compile("^\\s*<svg[^>]*\\bwidth=\"(\\d+)\"", Pattern.DOTALL);
    private static final Pattern ROOT_HEIGHT_PATTERN = Pattern.compile("^\\s*<svg[^>]*\\bheight=\"(\\d+)\"", Pattern.DOTALL);
    private static final String BASE_URL = "http://localhost:8080";

    @Test
    void rendersNoMetricsBadgeWhenVulnerabilitiesMissing() {
        String payload = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1}";

        given()
                .contentType("application/json")
                .body(payload)
                .when()
                .post("/v1/badge/vdr")
                .then()
                .statusCode(200)
                .contentType("image/svg+xml")
                .body(containsString("no metrics"));
    }

    @Test
    void rendersNoVulnsBadgeWhenEmptyVulnerabilities() {
        String payload = "{\"vulnerabilities\":[]}";

        given()
                .contentType("application/json")
                .body(payload)
                .when()
                .post("/v1/badge/vdr")
                .then()
                .statusCode(200)
                .contentType("image/svg+xml")
                .body(containsString("no vulns"))
                .body(not(containsString("no metrics")));
    }

    @Test
    void rendersMetricsBadgeFromVdr() {
        String payload = buildVdrWithCounts(1, 2, 3, 4, 5);

        given()
                .contentType("application/json")
                .body(payload)
                .when()
                .post("/v1/badge/vdr")
                .then()
                .statusCode(200)
                .contentType("image/svg+xml")
                .body(containsString(">1</text>"))
                .body(containsString(">2</text>"))
                .body(containsString(">3</text>"))
                .body(containsString(">4</text>"))
                .body(containsString(">5</text>"))
                .body(not(containsString("no vulns")));
    }

    @Test
    void rendersPolicyNoMetricsBadgeWhenVulnerabilitiesMissing() {
        String payload = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1}";

        given()
                .contentType("application/json")
                .body(payload)
                .when()
                .post("/v1/badge/vdr/violations")
                .then()
                .statusCode(200)
                .contentType("image/svg+xml")
                .body(containsString("no metrics"));
    }

    @Test
    void rendersPolicyViolationBadgeFromVdr() {
        String payload = buildVdrWithPolicyCounts(1, 2, 3, 0);

        given()
                .contentType("application/json")
                .body(payload)
                .when()
                .post("/v1/badge/vdr/violations")
                .then()
                .statusCode(200)
                .contentType("image/svg+xml")
                .body(containsString(">1</text>"))
                .body(containsString(">2</text>"))
                .body(containsString(">3</text>"))
                .body(not(containsString("no violations")));
    }

    @Test
    void usesConfiguredBaseUrlForHrefWhenComponentPresent() {
        String payload = "{\"metadata\":{\"component\":{\"name\":\"app\",\"version\":\"1.0.0\"}},\"vulnerabilities\":[]}";

        given()
                .contentType("application/json")
                .body(payload)
                .when()
                .post("/v1/badge/vdr")
                .then()
                .statusCode(200)
                .contentType("image/svg+xml")
                .body(containsString(BASE_URL + "/app/1.0.0"));
    }

    @Test
    void rendersCombinedBadgeHorizontallyByDefault() {
        String payload = buildCombinedVdr();

        String svg = given()
                .contentType("application/json")
                .body(payload)
                .when()
                .post("/v1/badge/vdr/combined")
                .then()
                .statusCode(200)
                .contentType("image/svg+xml")
                .extract()
                .asString();

        assertEquals(20, extractRootDimension(svg, ROOT_HEIGHT_PATTERN));
        assertTrue(svg.contains("dependencies"));
        assertTrue(svg.contains("policies"));
    }

    @Test
    void rendersCombinedBadgeStackedWhenRequested() {
        String payload = buildCombinedVdr();

        String svg = given()
                .contentType("application/json")
                .body(payload)
                .when()
                .post("/v1/badge/vdr/combined?stacked=true")
                .then()
                .statusCode(200)
                .contentType("image/svg+xml")
                .extract()
                .asString();

        assertEquals(40, extractRootDimension(svg, ROOT_HEIGHT_PATTERN));
        assertTrue(svg.contains("dependencies"));
        assertTrue(svg.contains("policies"));
    }

    private static String buildVdrWithCounts(int critical, int high, int medium, int low, int unassigned) {
        StringBuilder builder = new StringBuilder();
        builder.append("{\"vulnerabilities\":[");

        boolean first = true;
        first = appendSeverity(builder, first, "critical", critical);
        first = appendSeverity(builder, first, "high", high);
        first = appendSeverity(builder, first, "medium", medium);
        first = appendSeverity(builder, first, "low", low);
        appendSeverity(builder, first, "unknown", unassigned);

        builder.append("]}");
        return builder.toString();
    }

    private static String buildVdrWithPolicyCounts(int fail, int warn, int info, int none) {
        StringBuilder builder = new StringBuilder();
        builder.append("{\"vulnerabilities\":[");

        boolean first = true;
        first = appendPolicyViolation(builder, first, "fail", fail);
        first = appendPolicyViolation(builder, first, "warn", warn);
        first = appendPolicyViolation(builder, first, "info", info);
        appendPolicyViolation(builder, first, "none", none);

        builder.append("]}");
        return builder.toString();
    }

    private static boolean appendSeverity(StringBuilder builder, boolean first, String severity, int count) {
        for (int i = 0; i < count; i++) {
            if (!first) {
                builder.append(',');
            }
            builder.append("{\"ratings\":[{\"severity\":\"")
                    .append(severity)
                    .append("\"}]}");
            first = false;
        }
        return first;
    }

    private static boolean appendPolicyViolation(StringBuilder builder, boolean first, String level, int count) {
        for (int i = 0; i < count; i++) {
            if (!first) {
                builder.append(',');
            }
            builder.append("{\"properties\":[{\"name\":\"policyViolation\",\"value\":\"")
                    .append(level)
                    .append("\"}]}");
            first = false;
        }
        return first;
    }

    private static String buildCombinedVdr() {
        return "{\"vulnerabilities\":["
                + "{\"ratings\":[{\"severity\":\"critical\"}],\"properties\":[{\"name\":\"policyViolation\",\"value\":\"fail\"}]},"
                + "{\"ratings\":[{\"severity\":\"low\"}],\"properties\":[{\"name\":\"policyViolation\",\"value\":\"info\"}]}"
                + "]}";
    }

    private static int extractRootDimension(String svg, Pattern pattern) {
        Matcher matcher = pattern.matcher(svg);
        if (!matcher.find()) {
            throw new AssertionError("Missing root SVG dimension");
        }
        return Integer.parseInt(matcher.group(1));
    }
}
