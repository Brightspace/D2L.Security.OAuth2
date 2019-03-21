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

        private const string SignedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImZhN2MwN2E4LTQyYzgtNGM1Ny05YWYyLWNjZTEwYzI3MTAzMyJ9.eyJzY29wZXMiOiJhOmI6YyBhOmI6ZCIsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiZXhwIjoxNTQ2MzA0NDMwLCJuYmYiOjE1NDYzMDA4MDB9.KSWEUNYkXXDsC80DFdFO8vId3sMHLdsTrhDiPqDlae8zlIjoLADQDZYZ3UPCeC-3e7wnVQ99oQZaFFL7lcl92FgV165x7mzFMYEeHw0lSYNrY8Cu4qJjsgvAjrI6QO-xNdDmx27ttOpPWHSBXNUO68aZKL2Km1KJ9rQzWBaXxue2rNhw0nVCzi38TA8577RbXXnYjW3yg_aDo8pgYMFinXI7bMLxK5G7Nnzp8vAoPITPOzj_R_swdv6KmrrzQWq9GJzXQZqHjeoc3hSlBXefLcCzqbyxmJjUk6gilkfFwYVHLugA9KzHdJFYXr5ecDFLMdd_8a2gXwa-DAo8_KSSFQ";
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
                    new Claim("scopes", "a:b:c a:b:d")
                },
                notBefore: new DateTime( 2019, 1, 1, 0, 0, 0, DateTimeKind.Utc ),
                expiresAt: new DateTime( 2019, 1, 1, 1, 0, 30, DateTimeKind.Utc )
            );

            var signed = await m_tokenSigner.SignAsync( token );

            Assert.AreEqual( SignedToken, signed );
        }

        [Test]
        public async Task SignsUnsignedComplexToken() {
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

            var token = new UnsignedComplexToken(
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