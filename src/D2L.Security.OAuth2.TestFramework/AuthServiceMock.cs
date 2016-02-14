using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.TestFrameworks;
using D2L.Services;
using HttpMock;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.TestFramework {
	public sealed class AuthServiceMock {
		private readonly IHttpServer m_server;
		private readonly string m_host;

		private readonly ISanePublicKeyDataProvider m_publicKeyDataProvider;
		private readonly IPrivateKeyProvider m_privateKeyProvider;
		private readonly ITokenSigner m_tokenSigner;

		public enum KeyType {
			RSA = 1,
			ECDSA_P256 = 2,
			ECDSA_P384 = 3,
			ECDSA_P521 = 4
		};

		public AuthServiceMock( KeyType keyType = KeyType.RSA ) {
			m_server = HttpMockFactory.Create( out m_host );

#pragma warning disable 618
			m_publicKeyDataProvider = PublicKeyDataProviderFactory.CreateInternal( new InMemoryPublicKeyDataProvider() );
#pragma warning restore 618

			TimeSpan keyLifetime = TimeSpan.FromDays( 365 );
			TimeSpan keyRotationPeriod = TimeSpan.FromDays( 182 );

			switch( keyType ) {
				case KeyType.ECDSA_P256:
				case KeyType.ECDSA_P384:
				case KeyType.ECDSA_P521: {
						CngAlgorithm curve;
						switch( keyType ) {
							case KeyType.ECDSA_P521:
								curve = CngAlgorithm.ECDsaP521;
								break;
							case KeyType.ECDSA_P384:
								curve = CngAlgorithm.ECDsaP384;
								break;
							case KeyType.ECDSA_P256:
							default:
								curve = CngAlgorithm.ECDsaP256;
								break;
						}

						m_privateKeyProvider = EcDsaPrivateKeyProvider
							.Factory
							.Create(
								m_publicKeyDataProvider,
								keyLifetime,
								keyRotationPeriod,
								curve
							);
						break;
					}
				case KeyType.RSA:
				default: {
						m_privateKeyProvider = RsaPrivateKeyProvider
							.Factory
							.Create(
								m_publicKeyDataProvider,
								keyLifetime,
								keyRotationPeriod
							);
						break;
					}
			}

			m_tokenSigner = new TokenSigner( m_privateKeyProvider );
		}

		public async Task SetupJwks() {
			// Get a private key so public key is saved
			await m_privateKeyProvider.GetSigningCredentialsAsync().SafeAsync();

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
