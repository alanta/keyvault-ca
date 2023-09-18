using System.Diagnostics;
using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;

namespace CertificateIssuer.Infrastructure;

/// <summary>
/// Patch for request telemetry with empty operation name
/// The ServiceBusProcessor generates request telemetry with a generic name and empty operation name which is not very useful.
/// </summary>
internal class FixOperationNameTelemetryInitializer : ITelemetryInitializer
{
    public void Initialize(ITelemetry telemetry)
    {
        var activity = Activity.Current;
        
        if (telemetry is RequestTelemetry request && string.IsNullOrWhiteSpace(request.Context.Operation.Name))
        {
            if (activity != null)
            {
                request.Name = request.Context.Operation.Name = activity.DisplayName;
            }
        }

        if (activity != null && telemetry is RequestTelemetry request2 && (!request2.Success.HasValue || (activity.Status == ActivityStatusCode.Error && request2.Success == true)))
        {
            request2.Success = activity.Status != ActivityStatusCode.Error;
            request2.ResponseCode = activity.StatusDescription;
        }
    }
}
