using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

namespace KeyVaultCA.Tests.Tools;

public sealed class XunitLoggerFactory(ITestOutputHelper testOutputHelper) : ILoggerFactory
{
    public void AddProvider(ILoggerProvider provider)
    {
        // Not supported, but no need to throw
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new XunitLogger(testOutputHelper, categoryName);
    }

    public void Dispose()
    {
        // Nothing to do here
    }
}

public class XunitLogger(ITestOutputHelper testOutputHelper, string categoryName) : ILogger
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        return NoopDisposable.Instance;
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return true;
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        testOutputHelper.WriteLine($"{categoryName} [{eventId}] {formatter(state, exception)}");

        if (exception != null)
            testOutputHelper.WriteLine(exception.ToString());
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static readonly NoopDisposable Instance = new ();

        public void Dispose()
        {
            // Nothing to do here
        }
    }
}

public class XUnitLogger<T>(ITestOutputHelper helper) 
    : XunitLogger(helper, typeof(T).FullName), ILogger<T> where T : class
{
}