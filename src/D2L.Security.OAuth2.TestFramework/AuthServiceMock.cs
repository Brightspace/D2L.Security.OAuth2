using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Development;
using RichardSzalay.MockHttp;

namespace D2L.Security.OAuth2.TestFramework {
	public sealed class AuthServiceMock : IDisposable {
		private readonly MockHttpMessageHandler m_server;

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
			m_server = new MockHttpMessageHandler();

#pragma warning disable 618
			m_publicKeyDataProvider = PublicKeyDataProviderFactory.CreateInternal( new InMemoryPublicKeyDataProvider() );
#pragma warning restore 618

			TimeSpan keyLifetime = TimeSpan.FromDays( 365 );
			TimeSpan keyRotationPeriod = TimeSpan.FromDays( 182 );

			switch( keyType ) {
				case KeyType.ECDSA_P256:
				case KeyType.ECDSA_P384:
				case KeyType.ECDSA_P521: {
						ECCurve curve;
						switch( keyType ) {
							case KeyType.ECDSA_P521:
								curve = ECCurve.NamedCurves.nistP521;
								break;
							case KeyType.ECDSA_P384:
								curve = ECCurve.NamedCurves.nistP384;
								break;
							case KeyType.ECDSA_P256:
							default:
								curve = ECCurve.NamedCurves.nistP256;
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
			await m_privateKeyProvider.GetSigningCredentialsAsync().ConfigureAwait( false );

			var keys = await m_publicKeyDataProvider
				.GetAllAsync()
				.ConfigureAwait( false );

			List<object> keyDtos = new List<object>();
			foreach( JsonWebKey key in keys ) {
				object dto = key.ToJwkDto();
				keyDtos.Add( dto );

				m_server
					.When( HttpMethod.Get, $"http://localhost/jwk/{ key.Id }" )
					.Respond( "application/json", JsonSerializer.Serialize( dto ) );
			}

			string jwksJson = JsonSerializer.Serialize( new {
				keys = keyDtos
			} );

			m_server
				.When( HttpMethod.Get, $"http://localhost/.well-known/jwks" )
				.Respond( "application/json", jwksJson );
		}

		public Uri Host { get { return new Uri( "http://localhost" ); } }
		public HttpMessageHandler MockHandler => m_server;

		public async Task<string> SignTokenBackdoor( UnsignedToken token ) {
			return await m_tokenSigner
				.SignAsync( token )
				.ConfigureAwait( false );
		}

		public void Dispose() {
			if( m_server != null ) {
				m_server.Dispose();
			}
		}
	}
}
