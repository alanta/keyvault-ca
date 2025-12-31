using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Revocation.Ocsp.Hosting;

/// <summary>
/// Extension methods for mapping OCSP responder endpoints.
/// </summary>
public static class OcspEndpointExtensions
{
    /// <summary>
    /// Maps OCSP responder endpoints for handling certificate status requests.
    /// Implements RFC 6960 OCSP protocol with both POST and GET methods.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="pattern">The URL pattern for the OCSP endpoint. Default is "/".</param>
    /// <returns>The endpoint route builder for chaining.</returns>
    public static IEndpointRouteBuilder MapOcspResponder(
        this IEndpointRouteBuilder endpoints,
        string pattern = "/")
    {
        // POST endpoint (RFC 6960 standard method)
        endpoints.MapPost(pattern, async (
            HttpContext context,
            OcspResponseBuilder responseBuilder,
            ILogger<OcspResponseBuilder> logger) =>
        {
            try
            {
                // Read request body (size limit enforced by framework via RequestSizeLimitAttribute)
                using var ms = new MemoryStream();
                await context.Request.Body.CopyToAsync(ms);
                var requestBytes = ms.ToArray();

                if (requestBytes.Length == 0)
                {
                    logger.LogWarning("Empty OCSP request received");
                    return Results.BadRequest("Empty OCSP request");
                }

                logger.LogInformation(
                    "OCSP request received from {RemoteIpAddress}, size: {Size} bytes",
                    context.Connection.RemoteIpAddress,
                    requestBytes.Length);

                var responseBytes = await responseBuilder
                    .BuildResponseAsync(requestBytes, context.RequestAborted);

                logger.LogInformation(
                    "OCSP response generated, size: {Size} bytes",
                    responseBytes.Length);

                return Results.Bytes(responseBytes, "application/ocsp-response");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error processing OCSP request");
                return Results.Problem("Internal server error processing OCSP request");
            }
        })
        .WithName("OcspPost")
        .WithMetadata(new RequestSizeLimitAttribute(65536)) // RFC 6960 Appendix A.1 - Cap at 64KB to prevent DoS
        .WithOpenApi();

        // GET endpoint (RFC 6960 Appendix A.1 - optional)
        endpoints.MapGet($"{pattern}{{base64Request}}", async (
            HttpContext context,
            string base64Request,
            OcspResponseBuilder responseBuilder,
            ILogger<OcspResponseBuilder> logger) =>
        {
            try
            {
                // RFC 6960 Appendix A.1 - GET requests limited to ~1KB (typical URL length limits)
                const int MaxBase64Length = 1365; // ~1KB decoded (base64 = 4/3 overhead)
                if (base64Request.Length > MaxBase64Length)
                {
                    logger.LogWarning(
                        "OCSP GET request base64 too long: {Length} chars (max {Max})",
                        base64Request.Length, MaxBase64Length);
                    return Results.StatusCode(413); // Payload Too Large
                }

                // Base64URL decoding (replace URL-safe characters)
                var requestBytes = Convert.FromBase64String(
                    base64Request.Replace('_', '/').Replace('-', '+'));

                logger.LogInformation(
                    "OCSP GET request received from {RemoteIpAddress}, size: {Size} bytes",
                    context.Connection.RemoteIpAddress,
                    requestBytes.Length);

                var responseBytes = await responseBuilder
                    .BuildResponseAsync(requestBytes, context.RequestAborted);

                logger.LogInformation(
                    "OCSP response generated, size: {Size} bytes",
                    responseBytes.Length);

                return Results.Bytes(responseBytes, "application/ocsp-response");
            }
            catch (FormatException)
            {
                logger.LogWarning("Invalid base64 OCSP request received");
                return Results.BadRequest("Invalid base64 encoding");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error processing OCSP GET request");
                return Results.Problem("Internal server error processing OCSP request");
            }
        })
        .WithName("OcspGet")
        .WithOpenApi();

        return endpoints;
    }
}
