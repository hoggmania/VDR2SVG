package org.acme.badge;

import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.loader.ClasspathLoader;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import jakarta.enterprise.context.ApplicationScoped;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ApplicationScoped
class VdrBadgeRenderer {
    private static final Logger LOGGER = Logger.getLogger(VdrBadgeRenderer.class);
    private static final Pattern WIDTH_PATTERN = Pattern.compile("\\bwidth=\"(\\d+)\"");
    private static final Pattern HEIGHT_PATTERN = Pattern.compile("\\bheight=\"(\\d+)\"");
    private static final Pattern ID_PATTERN = Pattern.compile("\\bid=\"([^\"]+)\"");

    private final PebbleTemplate projectVulnsTemplate;
    private final PebbleTemplate projectVulnsNoneTemplate;
    private final PebbleTemplate projectVulnsNoMetricsTemplate;
    private final PebbleTemplate projectViolationsTemplate;
    private final PebbleTemplate projectViolationsNoneTemplate;
    private final PebbleTemplate projectViolationsNoMetricsTemplate;

    VdrBadgeRenderer() {
        ClasspathLoader loader = new ClasspathLoader(VdrBadgeRenderer.class.getClassLoader());
        PebbleEngine engine = new PebbleEngine.Builder()
                .loader(loader)
                .newLineTrimming(false)
                .build();
        this.projectVulnsTemplate = engine.getTemplate("templates/badge/project-vulns.peb");
        this.projectVulnsNoneTemplate = engine.getTemplate("templates/badge/project-vulns-none.peb");
        this.projectVulnsNoMetricsTemplate = engine.getTemplate("templates/badge/project-vulns-nometrics.peb");
        this.projectViolationsTemplate = engine.getTemplate("templates/badge/project-violations.peb");
        this.projectViolationsNoneTemplate = engine.getTemplate("templates/badge/project-violations-none.peb");
        this.projectViolationsNoMetricsTemplate = engine.getTemplate("templates/badge/project-violations-nometrics.peb");
    }

    String render(VdrMetrics metrics, String href, int roundedPixels) {
        Map<String, Object> context = new HashMap<>();
        context.put("roundedPixels", String.valueOf(roundedPixels));
        if (href != null && !href.isBlank()) {
            context.put("href", href);
        }

        if (metrics == null || !metrics.metricsAvailable()) {
            return writeSvg(projectVulnsNoMetricsTemplate, context);
        }

        if (metrics.total() > 0) {
            context.put("critical", String.valueOf(metrics.critical()));
            context.put("high", String.valueOf(metrics.high()));
            context.put("medium", String.valueOf(metrics.medium()));
            context.put("low", String.valueOf(metrics.low()));
            context.put("unassigned", String.valueOf(metrics.unassigned()));
            return writeSvg(projectVulnsTemplate, context);
        }

        return writeSvg(projectVulnsNoneTemplate, context);
    }

    String renderPolicyViolations(VdrViolationMetrics metrics, String href, int roundedPixels) {
        Map<String, Object> context = new HashMap<>();
        context.put("roundedPixels", String.valueOf(roundedPixels));
        if (href != null && !href.isBlank()) {
            context.put("href", href);
        }

        if (metrics == null || !metrics.metricsAvailable()) {
            return writeSvg(projectViolationsNoMetricsTemplate, context);
        }

        if (metrics.total() > 0) {
            context.put("fail", String.valueOf(metrics.fail()));
            context.put("warn", String.valueOf(metrics.warn()));
            context.put("info", String.valueOf(metrics.info()));
            return writeSvg(projectViolationsTemplate, context);
        }

        return writeSvg(projectViolationsNoneTemplate, context);
    }

    String renderCombined(VdrMetrics vulnMetrics,
                          VdrViolationMetrics violationMetrics,
                          String href,
                          int roundedPixels,
                          boolean stacked) {
        String vulnSvg = render(vulnMetrics, href, roundedPixels);
        String violationSvg = renderPolicyViolations(violationMetrics, href, roundedPixels);

        String left = uniquifyIds(vulnSvg, "vuln-");
        String right = uniquifyIds(violationSvg, "policy-");

        SvgDimensions leftDimensions = parseDimensions(left);
        SvgDimensions rightDimensions = parseDimensions(right);

        int width = stacked ? Math.max(leftDimensions.width(), rightDimensions.width())
                : leftDimensions.width() + rightDimensions.width();
        int height = stacked ? leftDimensions.height() + rightDimensions.height()
                : Math.max(leftDimensions.height(), rightDimensions.height());

        int rightX = stacked ? 0 : leftDimensions.width();
        int rightY = stacked ? leftDimensions.height() : 0;

        String positionedLeft = injectPosition(left, 0, 0);
        String positionedRight = injectPosition(right, rightX, rightY);

        return "<svg width=\"" + width + "\" height=\"" + height + "\" viewBox=\"0 0 " + width + " " + height + "\" " +
                "xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">" +
                positionedLeft +
                positionedRight +
                "</svg>";
    }

    private String writeSvg(PebbleTemplate template, Map<String, Object> context) {
        try (Writer writer = new StringWriter()) {
            template.evaluate(writer, context);
            return writer.toString();
        } catch (IOException e) {
            LOGGER.error("Failed to render SVG badge", e);
            throw new IllegalStateException("Failed to render SVG badge", e);
        }
    }

    private SvgDimensions parseDimensions(String svg) {
        String tag = extractRootSvgTag(svg);
        int width = parseDimension(tag, WIDTH_PATTERN, "width");
        int height = parseDimension(tag, HEIGHT_PATTERN, "height");
        return new SvgDimensions(width, height);
    }

    private int parseDimension(String tag, Pattern pattern, String attribute) {
        Matcher matcher = pattern.matcher(tag);
        if (!matcher.find()) {
            throw new IllegalStateException("Missing " + attribute + " in SVG root");
        }
        return Integer.parseInt(matcher.group(1));
    }

    private String extractRootSvgTag(String svg) {
        int start = svg.indexOf("<svg");
        if (start < 0) {
            throw new IllegalStateException("Missing SVG root");
        }
        int end = svg.indexOf(">", start);
        if (end < 0) {
            throw new IllegalStateException("Malformed SVG root");
        }
        return svg.substring(start, end + 1);
    }

    private String injectPosition(String svg, int x, int y) {
        int start = svg.indexOf("<svg");
        if (start < 0) {
            return svg;
        }
        int insertAt = start + 4;
        return svg.substring(0, insertAt) +
                " x=\"" + x + "\" y=\"" + y + "\"" +
                svg.substring(insertAt);
    }

    private String uniquifyIds(String svg, String prefix) {
        Set<String> ids = new HashSet<>();
        Matcher matcher = ID_PATTERN.matcher(svg);
        while (matcher.find()) {
            ids.add(matcher.group(1));
        }

        String updated = svg;
        for (String id : ids) {
            String prefixed = prefix + id;
            updated = updated.replace("id=\"" + id + "\"", "id=\"" + prefixed + "\"");
            updated = updated.replace("url(#" + id + ")", "url(#" + prefixed + ")");
            updated = updated.replace("xlink:href=\"#" + id + "\"", "xlink:href=\"#" + prefixed + "\"");
            updated = updated.replace("href=\"#" + id + "\"", "href=\"#" + prefixed + "\"");
        }
        return updated;
    }

    private record SvgDimensions(int width, int height) {
    }
}
