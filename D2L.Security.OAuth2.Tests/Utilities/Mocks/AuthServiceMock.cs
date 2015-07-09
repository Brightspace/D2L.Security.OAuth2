using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Development;
using HttpMock;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Tests.Utilities.Mocks {
	internal sealed class AuthServiceMock {
		private readonly IHttpServer m_server;
		private readonly string m_host;
		private readonly IPublicKeyDataProvider m_publicKeyDataProvider;
		private readonly ITokenSigner m_tokenSigner;

		public AuthServiceMock() {
			m_server = HttpMockFactory.Create( out m_host );

			RSAParameters parameters;
			using( RSACryptoServiceProvider csp = new RSACryptoServiceProvider( dwKeySize: Keys.Constants.GENERATED_RSA_KEY_SIZE ) ) {
				parameters = csp.ExportParameters( includePrivateParameters: true );
			}

			Guid keyId = Guid.NewGuid();

			TimeSpan keyLifetime = TimeSpan.FromDays( 365 );

#pragma warning disable 618
			IPrivateKeyProvider privateKeyProvider = new StaticPrivateKeyProvider( keyId, parameters );
			m_publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
#pragma warning restore 618

			m_publicKeyDataProvider.SaveAsync( new RsaJsonWebKey( keyId, DateTime.UtcNow + keyLifetime, parameters ) );
			m_tokenSigner = new TokenSigner( privateKeyProvider );
		}

		public async Task SetupJwks() {
			var keys = await m_publicKeyDataProvider
				.GetAllAsync()
				.SafeAsync();

			IEnumerable<object> keysDto = keys
				.Select( k => k.ToJwkDto() );

			var jwksDto = new {
				keys = keysDto
			};

			string jwksJson = JsonConvert.SerializeObject( jwksDto );

			m_server
				.Stub( r => r.Get( "/.well-known/jwks" ) )
				.Return( jwksJson )
				.OK();
		}

		public Uri Host { get { return new Uri( m_host ); } }

		public async Task<string> SignTokenBackdoor( UnsignedToken token ) {
			return await m_tokenSigner
				.SignAsync( token )
				.SafeAsync();
		}
	}
}
