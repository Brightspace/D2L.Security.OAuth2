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

        private const string SignedToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhN2MwN2E4LTQyYzgtNGM1Ny05YWYyLWNjZTEwYzI3MTAzMyIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE1NDYzMDA4MDAsImV4cCI6MTU0NjMwNDQzMCwiaXNzIjoiaXNzdWVyIiwiYXVkIjoiYXVkaWVuY2UiLCJpYXQiOjE1NDYzMDA4MDAsInNjb3BlcyI6ImE6YjpjIGE6YjpkIiwidGVuYW50aWQiOiIzMjVjYjQ2Yi00ODhkLTQwNjEtYWEyYy1lZWY1YTEyYjZiN2MifQ.eqH5TlV5TN4w4b9RoIUBaeTlpkyQ15z2MAXRdh7smn90ZN0wxHtThxqUGfdLsFWqbn5e1hVS69-wQcDBBwl5m0p1AgCS1LSHd9rT4Eh6lM9_A_NoLamF5LGBZqm_SoE4DaLLUgwYc2YbOFs577AU34WmgE6oZaG_j6JMzxAs8lgyhpj-iFME2mSJTpUK4H1RgQ03my0zpUvuKFFS2NJfPF2Vs_aXh0L1PKV6MYoNMJHZmEyLSpj36R8zIPyFGkbrxztqmTsg08yKjHiZgp9FBx_sDm-nwAMlpSIn4_xpfK4U50mLkIsejvr86gSqVcgHht8Au5FYY8Y4x2MDs8jAJg";
        private const string SignedComplexToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhN2MwN2E4LTQyYzgtNGM1Ny05YWYyLWNjZTEwYzI3MTAzMyIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE1NDYzMDA4MDAsImV4cCI6MTU0NjMwNDQzMCwiaXNzIjoiaXNzdWVyIiwiYXVkIjoiYXVkaWVuY2UiLCJpYXQiOjE1NDYzMDA4MDAsImh0dHBzOi8vc2VydmljZS5jb20vY2xhaW0vdmVyc2lvbiI6IjEuMC4wIiwiaHR0cHM6Ly9zZXJ2aWNlLmNvbS9jbGFpbS9yb2xlcyI6WyJodHRwczovL3NlcnZpY2UuY29tL3JvbGVzI2FkbWluaXN0cmF0b3IiLCJodHRwczovL3NlcnZpY2UuY29tL3JvbGVzI3VzZXIiXSwiaHR0cHM6Ly9zZXJ2aWNlLmNvbS9jbGFpbS9jb250ZXh0Ijp7ImlkIjoiYzFkODg3ZjAtYTFhMy00YmNhLWFlMjUtYzM3NWVkY2MxMzFhIiwidHlwZSI6WyJodHRwczovL3NlcnZpY2UuY29tL3R5cGVzI3R5cGUiXX19.FjG7jBeAZQGjdxkTIjoGjbtf-Jz89Tje7TWSdy401NDI5ns7c6MORrpNHqCIUs6PO4zbHnmf1SBVAC2ALJWEJ4K5KH4WlZxm9VYyUQ7xrhWQurGp7szK9pUmJqvb0mTB9fOg-BMjICknfHxXnkXIR9tYL8MEbK3jaz1wDWF4V6qlTY-TcHt4mDbK5PG4e1K-ZgSG1Jgci_avtYh6gv9BqGqYB0wyu5OKwRTXrtjv5roDqNFO9G_aPUzmzI_9IgwLqJ3XahSbwgHLr49yW6kL0N01rWHvi1Clb3fP7Jl9ec-ANJkKPFXea4ZsdmZrlBdHv3G94JkaDf9aWaSUxNWZSQ";

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
                notBefore: new DateTime( 2019, 1, 1, 0, 0, 0,  DateTimeKind.Utc ),
                expiresAt: new DateTime( 2019, 1, 1, 1, 0, 30, DateTimeKind.Utc ),
                issuedAt:  new DateTime( 2019, 1, 1, 0, 0, 0,  DateTimeKind.Utc )
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
                notBefore: new DateTime( 2019, 1, 1, 0, 0, 0,  DateTimeKind.Utc ),
                expiresAt: new DateTime( 2019, 1, 1, 1, 0, 30, DateTimeKind.Utc ),
                issuedAt:  new DateTime( 2019, 1, 1, 0, 0, 0,  DateTimeKind.Utc )
            );

            var signed = await m_tokenSigner.SignAsync( token );

            Assert.AreEqual( SignedComplexToken, signed );
        }
    }
}
