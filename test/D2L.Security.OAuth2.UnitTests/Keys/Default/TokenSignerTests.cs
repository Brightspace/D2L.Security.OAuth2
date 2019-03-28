using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.TestFramework;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Keys.Default {
    [TestFixture]
    internal sealed class TokenSignerTests {
        private static readonly Guid TestKeyId = TestStaticKeyProvider.TestKeyId;

        private const string SignedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImZhN2MwN2E4LTQyYzgtNGM1Ny05YWYyLWNjZTEwYzI3MTAzMyJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImV4cCI6MTU0NjMwNDQzMCwibmJmIjoxNTQ2MzAwODAwLCJzY29wZXMiOiJhOmI6YyBhOmI6ZCIsInRlbmFudGlkIjoiMzI1Y2I0NmItNDg4ZC00MDYxLWFhMmMtZWVmNWExMmI2YjdjIn0.h_rwqjjXwjvG5f7Vv7TEslOzTqLal2DvuYD6qyzqXnoRylFUEkrMpz-tLbWHesEyab1ZNayjwt8PjykXjrQbJeka29WD1JDMss5VjloOOpI9Vby_IzCbzh8xLaL1q22KY_bfr8VMum2wuVHw0v9sriTiHtGtyfSxuplXQ4HZubuzhl3v8uvxqsVF5ByuGiYQoZ3KyFVGx4JIYo1-wR3vdamqN5qfT4Q5_I-Je9QfFNhQRNRMDwgvW6FLTgtMRYpYwKYldJWZjR1jyUjeGlOGrHrA7ObWsxs4MMyuHR-mfWtCkcy28fg0CiyB5PSUIQZ9UFMndtgqaHvq3POgALBwlA";
        private const string SignedComplexToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImZhN2MwN2E4LTQyYzgtNGM1Ny05YWYyLWNjZTEwYzI3MTAzMyJ9.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImV4cCI6MTU0NjMwNDQzMCwibmJmIjoxNTQ2MzAwODAwLCJodHRwczovL3NlcnZpY2UuY29tL2NsYWltL3ZlcnNpb24iOiIxLjAuMCIsImh0dHBzOi8vc2VydmljZS5jb20vY2xhaW0vcm9sZXMiOlsiaHR0cHM6Ly9zZXJ2aWNlLmNvbS9yb2xlcyNhZG1pbmlzdHJhdG9yIiwiaHR0cHM6Ly9zZXJ2aWNlLmNvbS9yb2xlcyN1c2VyIl0sImh0dHBzOi8vc2VydmljZS5jb20vY2xhaW0vY29udGV4dCI6eyJpZCI6ImMxZDg4N2YwLWExYTMtNGJjYS1hZTI1LWMzNzVlZGNjMTMxYSIsInR5cGUiOlsiaHR0cHM6Ly9zZXJ2aWNlLmNvbS90eXBlcyN0eXBlIl19fQ.TpLnfQTntKz-ilrF0njvGBUXuqA4Wlx3VE11ZWmsVb4DrGQnqYF5ajA4L5GWA8eK0cvv_Nnf3n37VVsJuxr3rn-y7sqxLqXQcCU74s2eefX6u0lpYNN2sM_bRdHSm7qw3aT06xDv0Adyh2EWWnDGUanug-UBf7wIt6H4HvOdn4rNPimIFMmFBSO2ZjqOvcbjqsqec2THg6FqZQHVKlLdHB3BELOzpLMiUEV5-7VHVli8wRoZzP8PQmlqO7_v1-g-mldzHEbmwfLNE11AIQRaI7RJiSuqkEpCbnKH-j_epVSrPCThiCKV76XXAubb6y9188w7watjsG1m656yxFNemQ";

        private IPrivateKeyProvider m_privateKeyProvider;
        private ITokenSigner m_tokenSigner;

        [OneTimeSetUp]
        public void OneTimeSetUp() {
#pragma warning disable 618
            m_privateKeyProvider = new StaticPrivateKeyProvider(
                keyId: TestKeyId,
                rsaParameters: TestStaticKeyProvider.TestRSAParameters );
#pragma warning restore 618
            m_tokenSigner = new TokenSigner( m_privateKeyProvider );
        }

        [Test]
        public async Task SignsUnsignedToken() {
            var token = new UnsignedToken(
                issuer: "issuer",
                audience: "audience",
                claims: new List<Claim>() {
                    new Claim("scopes", "a:b:c a:b:d"),
                    new Claim("tenantid", "325cb46b-488d-4061-aa2c-eef5a12b6b7c")
                },
                notBefore: new DateTime( 2019, 1, 1, 0, 0, 0, DateTimeKind.Utc ),
                expiresAt: new DateTime( 2019, 1, 1, 1, 0, 30, DateTimeKind.Utc )
            );

            var signed = await m_tokenSigner.SignAsync( token );

            Assert.AreEqual( SignedToken, signed );
        }

        [Test]
        public async Task SignsUnsignedToken_WithComplexClaims() {
            var claims = new Dictionary<string, object>();
            claims.Add( "https://service.com/claim/version", "1.0.0" );
            claims.Add( "https://service.com/claim/roles", new string[] {
                "https://service.com/roles#administrator",
                "https://service.com/roles#user"
            } );
            claims.Add( "https://service.com/claim/context", new Dictionary<string, object>() {
                {"id", "c1d887f0-a1a3-4bca-ae25-c375edcc131a" },
                {"type", new string[] { "https://service.com/types#type" } }
            } );

            var token = new UnsignedToken(
                issuer: "issuer",
                audience: "audience",
                claims: claims,
                notBefore: new DateTime( 2019, 1, 1, 0, 0, 0, DateTimeKind.Utc ),
                expiresAt: new DateTime( 2019, 1, 1, 1, 0, 30, DateTimeKind.Utc )
            );

            var signed = await m_tokenSigner.SignAsync( token );

            Assert.AreEqual( SignedComplexToken, signed );
        }
    }
}