package org.acme.badge;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

@Path("/v1/badge")
@Consumes(MediaType.APPLICATION_JSON)
@Produces("image/svg+xml")
@Tag(name = "badge")
public class VdrBadgeResource {
    private static final int DEFAULT_ROUNDED_PIXELS = 3;

    private final VdrMetricsService metricsService;
    private final VdrBadgeRenderer badgeRenderer;
    private final VdrBadgeLinkService linkService;

    @Inject
    VdrBadgeResource(VdrMetricsService metricsService, VdrBadgeRenderer badgeRenderer, VdrBadgeLinkService linkService) {
        this.metricsService = metricsService;
        this.badgeRenderer = badgeRenderer;
        this.linkService = linkService;
    }

    @POST
    @Path("/vdr")
    @Operation(
            summary = "Render an SVG badge from a CycloneDX VDR",
            description = "Accepts a CycloneDX VDR JSON payload and returns a Dependency-Track-style SVG badge."
    )
    @APIResponses({
            @APIResponse(
                    responseCode = "200",
                    description = "SVG badge rendered from the VDR",
                    content = @Content(mediaType = "image/svg+xml", schema = @Schema(type = SchemaType.STRING))
            ),
            @APIResponse(responseCode = "400", description = "Invalid VDR payload")
    })
    public Response renderBadge(
            @RequestBody(
                    required = true,
                    content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(type = SchemaType.OBJECT))
            )
            JsonNode vdr,
            @Parameter(description = "Optional URL to link the badge to.")
            @QueryParam("href") String href,
            @Parameter(description = "Corner radius in pixels.", schema = @Schema(type = SchemaType.INTEGER, defaultValue = "3"))
            @QueryParam("roundedPixels") Integer roundedPixels) {
        int rounded = roundedPixels != null ? roundedPixels : DEFAULT_ROUNDED_PIXELS;
        VdrMetrics metrics = metricsService.summarize(vdr);
        String resolvedHref = linkService.resolveHref(vdr, href);
        String svg = badgeRenderer.render(metrics, resolvedHref, rounded);
        return Response.ok(svg).build();
    }

    @POST
    @Path("/vdr/violations")
    @Operation(
            summary = "Render a policy violations badge from a CycloneDX VDR",
            description = "Reads policy violation properties from vulnerabilities and returns an SVG badge."
    )
    @APIResponses({
            @APIResponse(
                    responseCode = "200",
                    description = "SVG badge rendered from the VDR policy violations",
                    content = @Content(mediaType = "image/svg+xml", schema = @Schema(type = SchemaType.STRING))
            ),
            @APIResponse(responseCode = "400", description = "Invalid VDR payload")
    })
    public Response renderPolicyViolations(
            @RequestBody(
                    required = true,
                    content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(type = SchemaType.OBJECT))
            )
            JsonNode vdr,
            @Parameter(description = "Optional URL to link the badge to.")
            @QueryParam("href") String href,
            @Parameter(description = "Corner radius in pixels.", schema = @Schema(type = SchemaType.INTEGER, defaultValue = "3"))
            @QueryParam("roundedPixels") Integer roundedPixels) {
        int rounded = roundedPixels != null ? roundedPixels : DEFAULT_ROUNDED_PIXELS;
        VdrViolationMetrics metrics = metricsService.summarizePolicyViolations(vdr);
        String resolvedHref = linkService.resolveHref(vdr, href);
        String svg = badgeRenderer.renderPolicyViolations(metrics, resolvedHref, rounded);
        return Response.ok(svg).build();
    }

    @POST
    @Path("/vdr/combined")
    @Operation(
            summary = "Render a combined vulnerabilities and policy violations badge",
            description = "Returns a single SVG containing the vulnerabilities badge and the policy violations badge."
    )
    @APIResponses({
            @APIResponse(
                    responseCode = "200",
                    description = "Combined SVG badge rendered from the VDR",
                    content = @Content(mediaType = "image/svg+xml", schema = @Schema(type = SchemaType.STRING))
            ),
            @APIResponse(responseCode = "400", description = "Invalid VDR payload")
    })
    public Response renderCombinedBadge(
            @RequestBody(
                    required = true,
                    content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(type = SchemaType.OBJECT))
            )
            JsonNode vdr,
            @Parameter(description = "Optional URL to link the badge to.")
            @QueryParam("href") String href,
            @Parameter(description = "Corner radius in pixels.", schema = @Schema(type = SchemaType.INTEGER, defaultValue = "3"))
            @QueryParam("roundedPixels") Integer roundedPixels,
            @Parameter(description = "Stack badges vertically when true.")
            @QueryParam("stacked") Boolean stacked) {
        int rounded = roundedPixels != null ? roundedPixels : DEFAULT_ROUNDED_PIXELS;
        boolean stackBadges = Boolean.TRUE.equals(stacked);
        VdrMetrics vulnerabilityMetrics = metricsService.summarize(vdr);
        VdrViolationMetrics violationMetrics = metricsService.summarizePolicyViolations(vdr);
        String resolvedHref = linkService.resolveHref(vdr, href);
        String svg = badgeRenderer.renderCombined(vulnerabilityMetrics, violationMetrics, resolvedHref, rounded, stackBadges);
        return Response.ok(svg).build();
    }
}
