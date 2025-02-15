using Azure.Messaging;
using FluentAssertions;

namespace KeyVaultCA.Tests
{
    public class CloudEvents
    {
        //
        //Azure.Messaging.EventGrid.SystemEvents.KeyVaultCertificateExpiredEventData

        [Fact]
        public static void ParseEvent()
        {
            var cloudEvent = CloudEvent.Parse(new BinaryData(eventGridEvent));

            cloudEvent.Type.Should().Be("Microsoft.KeyVault.SecretNewVersionCreated");

            var systemEvent = cloudEvent.Data
                .ToObjectFromJson<Azure.Messaging.EventGrid.SystemEvents.KeyVaultSecretNewVersionCreatedEventData>();

            systemEvent.Should().NotBeNull();
            systemEvent.ObjectName.Should().Be("TestSecret");
        }

        private static string eventGridEvent =
            @"{""id"":""5f7af610-4458-4727-a6ea-fa50b72cb106"",""source"":""/subscriptions/4ba76f60-d312-4ca0-8107-bc3e567cb53d/resourceGroups/kv-ca/providers/Microsoft.KeyVault/vaults/mvv-kv-ca"",""specversion"":""1.0"",""type"":""Microsoft.KeyVault.SecretNewVersionCreated"",""subject"":""TestSecret"",""time"":""2023-09-20T06:44:41.8010934Z"",""data"":{""Id"":""https://mvv-kv-ca.vault.azure.net/secrets/TestSecret/4d0663e10f7c4c649762b2d2147cc28b"",""VaultName"":""mvv-kv-ca"",""ObjectType"":""Secret"",""ObjectName"":""TestSecret"",""Version"":""4d0663e10f7c4c649762b2d2147cc28b"",""NBF"":null,""EXP"":1758351039}}";

    }

    /*public class Rootobject
    {
        public Class1[] Property1 { get; set; }
    }
    
    public class CloudEvent<TData>
    {
        public string id { get; set; }
        public string source { get; set; }
        public string subject { get; set; }
        public string type { get; set; }
        public DateTime time { get; set; }
        public TData data { get; set; }
        public string specversion { get; set; }
    }

    public class KeyVaultData
    {
        public string Id { get; set; }
        public string VaultName { get; set; }
        public string ObjectType { get; set; }
        public string ObjectName { get; set; }
        public string Version { get; set; }
        public string NBF { get; set; }
        public string EXP { get; set; }
    }*/

}
