using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Keys.Local.Default;
using HttpMock;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Tests.Utilities.Mocks {
	internal sealed class AuthServiceMock {
		private readonly IHttpServer m_server;
		private readonly string m_host;
		private readonly IPublicKeyProvider m_publicKeyProvider;
		private readonly IKeyManager m_keyManager;

		public AuthServiceMock() {
			m_server = HttpMockFactory.Create( out m_host );

			RSAParameters parameters;
			using( RSACryptoServiceProvider csp = new RSACryptoServiceProvider( dwKeySize: 2048 ) ) {
				parameters = csp.ExportParameters( includePrivateParameters: true );
			}

			Guid keyId = Guid.NewGuid();

			TimeSpan keyLifetime = TimeSpan.FromDays( 365 );

#pragma warning disable 618
			IPrivateKeyProvider privateKeyProvider = new StaticPrivateKeyProvider( keyId, parameters );
			IPublicKeyDataProvider publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
#pragma warning restore 618

			publicKeyDataProvider.SaveAsync( new RsaJsonWebKey( keyId, DateTime.UtcNow + keyLifetime, parameters ) );
			m_publicKeyProvider = new PublicKeyProvider( publicKeyDataProvider, keyLifetime );
			m_keyManager = new KeyManager( m_publicKeyProvider, privateKeyProvider );
		}

		public async Task SetupJwks() {
			var keys = await m_publicKeyProvider
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
			return await m_keyManager
				.SignAsync( token )
				.SafeAsync();
		}
	}
}
