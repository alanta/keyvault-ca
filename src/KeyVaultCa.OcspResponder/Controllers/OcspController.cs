using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using KeyVaultCa.Revocation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.OcspResponder.Controllers;

[ApiController]
[Route("")]
public class OcspController : ControllerBase
{
    private readonly OcspResponseBuilder _responseBuilder;
    private readonly ILogger<OcspController> _logger;

    public OcspController(OcspResponseBuilder responseBuilder, ILogger<OcspController> logger)
    {
        _responseBuilder = responseBuilder;
        _logger = logger;
    }

    /// <summary>
    /// Handle OCSP requests via HTTP POST (RFC 6960 section 2.1)
    /// </summary>
    [HttpPost]
    [Consumes("application/ocsp-request")]
    [Produces("application/ocsp-response")]
    public async Task<IActionResult> Post(CancellationToken ct)
    {
        try
        {
            // Read the OCSP request from the body
            using var ms = new MemoryStream();
            await Request.Body.CopyToAsync(ms, ct);
            var requestBytes = ms.ToArray();

            _logger.LogInformation("Received OCSP request via POST ({size} bytes)", requestBytes.Length);

            // Build and return the OCSP response
            var responseBytes = await _responseBuilder.BuildResponseAsync(requestBytes, ct);

            _logger.LogInformation("Returning OCSP response ({size} bytes)", responseBytes.Length);

            return File(responseBytes, "application/ocsp-response");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing OCSP POST request");
            return StatusCode(500);
        }
    }

    /// <summary>
    /// Handle OCSP requests via HTTP GET (RFC 6960 Appendix A.1)
    /// The request is base64-encoded and URL-encoded in the path
    /// </summary>
    [HttpGet("{base64Request}")]
    [Produces("application/ocsp-response")]
    public async Task<IActionResult> Get(string base64Request, CancellationToken ct)
    {
        try
        {
            _logger.LogInformation("Received OCSP request via GET");

            // Decode the base64-encoded request
            var requestBytes = Convert.FromBase64String(base64Request);

            _logger.LogInformation("Decoded OCSP request ({size} bytes)", requestBytes.Length);

            // Build and return the OCSP response
            var responseBytes = await _responseBuilder.BuildResponseAsync(requestBytes, ct);

            _logger.LogInformation("Returning OCSP response ({size} bytes)", responseBytes.Length);

            return File(responseBytes, "application/ocsp-response");
        }
        catch (FormatException ex)
        {
            _logger.LogWarning(ex, "Invalid base64 encoding in GET request");
            return BadRequest("Invalid base64 encoding");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing OCSP GET request");
            return StatusCode(500);
        }
    }
}
