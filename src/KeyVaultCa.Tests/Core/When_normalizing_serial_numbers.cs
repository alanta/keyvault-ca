using KeyVaultCa.Core;
using Shouldly;

namespace KeyVaultCa.Tests.Core;

public class When_normalizing_serial_numbers
{
    [Fact]
    public void It_should_trim_leading_zeros()
    {
        SerialNumberHelper.Normalize("00AB12CD").ShouldBe("AB12CD");
    }

    [Fact]
    public void It_should_trim_multiple_leading_zeros()
    {
        SerialNumberHelper.Normalize("0000AB12CD").ShouldBe("AB12CD");
    }

    [Fact]
    public void It_should_convert_to_uppercase()
    {
        SerialNumberHelper.Normalize("ab12cd").ShouldBe("AB12CD");
    }

    [Fact]
    public void It_should_handle_leading_zeros_and_lowercase()
    {
        SerialNumberHelper.Normalize("00ab12cd").ShouldBe("AB12CD");
    }

    [Fact]
    public void It_should_return_zero_for_single_zero()
    {
        SerialNumberHelper.Normalize("0").ShouldBe("0");
    }

    [Fact]
    public void It_should_return_zero_for_multiple_zeros()
    {
        SerialNumberHelper.Normalize("0000").ShouldBe("0");
    }

    [Fact]
    public void It_should_preserve_already_canonical_serial()
    {
        SerialNumberHelper.Normalize("AB12CD").ShouldBe("AB12CD");
    }

    [Fact]
    public void It_should_handle_odd_length_hex()
    {
        // BigInteger.ToString(16) may produce odd-length hex like "F" instead of "0F"
        SerialNumberHelper.Normalize("F").ShouldBe("F");
    }

    [Fact]
    public void It_should_handle_realistic_serial_number()
    {
        // Typical X509Certificate2.SerialNumber output (40 hex chars = 20 bytes)
        SerialNumberHelper.Normalize("5CD67951EAFAEDB509A67169DA25DDE1DA28F04B")
            .ShouldBe("5CD67951EAFAEDB509A67169DA25DDE1DA28F04B");
    }

    [Fact]
    public void It_should_handle_serial_with_leading_zero_byte()
    {
        // DER encoding adds 0x00 prefix when high bit is set — common case (~50% of serials)
        SerialNumberHelper.Normalize("005CD67951EAFAEDB509A67169DA25DDE1DA28F04B")
            .ShouldBe("5CD67951EAFAEDB509A67169DA25DDE1DA28F04B");
    }

    [Fact]
    public void Should_produce_same_result_for_x509_and_biginteger_formats()
    {
        // Simulates: X509Certificate2.SerialNumber returns "00AB12CD"
        // while BigInteger.ToString(16) returns "AB12CD" — both must normalize the same
        var fromX509 = SerialNumberHelper.Normalize("00AB12CD");
        var fromBigInteger = SerialNumberHelper.Normalize("AB12CD");

        fromX509.ShouldBe(fromBigInteger);
    }

    [Fact]
    public void Should_throw_for_null_input()
    {
        Should.Throw<ArgumentNullException>(() => SerialNumberHelper.Normalize(null!));
    }
}
