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
        private static readonly string TestKeyId = TestStaticKeyProvider.TestKeyId;

        private const string SignedToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhN2MwN2E4LTQyYzgtNGM1Ny05YWYyLWNjZTEwYzI3MTAzMyIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE1NDYzMDA4MDAsImV4cCI6MTU0NjMwNDQzMCwiaXNzIjoiaXNzdWVyIiwiYXVkIjoiYXVkaWVuY2UiLCJzY29wZXMiOiJhOmI6YyBhOmI6ZCIsInRlbmFudGlkIjoiMzI1Y2I0NmItNDg4ZC00MDYxLWFhMmMtZWVmNWExMmI2YjdjIn0.HB_hkyPQE2jfhTaRf64qqWjo6HkJcZILYGnjccsXTrjJpHTrxPlu7gmmolTXIBTplKlB08O2Q-Q9NHtDg5XtCTsm_PNjy6G8OJlu1NEMMQUS-V7phNVpOGxIMQamj_5jI8uz1Xx2nzj333mE9tJXvuba8GWeTbPlYKLd7kI83wGAYVNAUxV6ZkaoYu5Uvj3NRByAeXtDhXdhdk6UPeHECfaei3OE6NlGwuJIB-pts3V4JDq0xOIUCt84lFy27aiQyILXoKrwPdkboFxXRthtLw6aIl_Ce8fSCjAxDmMNkV6pW0FCCl_nWrVooTeXEcDkCr5c7NRRyAOHky-n5WDISQ";
        private const string SignedComplexToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhN2MwN2E4LTQyYzgtNGM1Ny05YWYyLWNjZTEwYzI3MTAzMyIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE1NDYzMDA4MDAsImV4cCI6MTU0NjMwNDQzMCwiaXNzIjoiaXNzdWVyIiwiYXVkIjoiYXVkaWVuY2UiLCJodHRwczovL3NlcnZpY2UuY29tL2NsYWltL3ZlcnNpb24iOiIxLjAuMCIsImh0dHBzOi8vc2VydmljZS5jb20vY2xhaW0vcm9sZXMiOlsiaHR0cHM6Ly9zZXJ2aWNlLmNvbS9yb2xlcyNhZG1pbmlzdHJhdG9yIiwiaHR0cHM6Ly9zZXJ2aWNlLmNvbS9yb2xlcyN1c2VyIl0sImh0dHBzOi8vc2VydmljZS5jb20vY2xhaW0vY29udGV4dCI6eyJpZCI6ImMxZDg4N2YwLWExYTMtNGJjYS1hZTI1LWMzNzVlZGNjMTMxYSIsInR5cGUiOlsiaHR0cHM6Ly9zZXJ2aWNlLmNvbS90eXBlcyN0eXBlIl19fQ.eMvY5Srt0I-tQ-4gWi5EXmZ897IVymLSywUd6DI6QYcD4zCVoNMus7VbwcJm8P3Sb6-JUHS7ZMBuaA3E0xG4xmPtrnCUkEETfKgjQmmHGHwx0ZoBnsjYhTRUk_imf5DMPWIUS8S01QYz1pbFhxsKQGX2h-dTpkPa_PH2vCd-5TlKKGrOCkV4c60RpkQuj1UVcxpHpCecPGT-ulIA7loK2mCSov5lk_hvnmvFTH-F0eOf-CI9ebDvfWCSnKGlsBp6TAo9PIDDtH4GiwLrW6ZsSGMXGE5uWLFDGtZq-OETV6EMEOA-N4MJJ_34tJ0SPVSJ_8ApyP8_HBzGb9ED8PQBOQ";

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
                claims: new Dictionary<string, object>() {
					{ "scopes", "a:b:c a:b:d" },
					{ "tenantid", "325cb46b-488d-4061-aa2c-eef5a12b6b7c" }
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
