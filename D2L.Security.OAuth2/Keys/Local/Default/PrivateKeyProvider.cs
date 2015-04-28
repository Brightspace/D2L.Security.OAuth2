using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys.Local.Default {
	internal sealed class PrivateKeyProvider : IPrivateKeyProvider {
		
		private readonly IPublicKeyDataProvider m_publicKeyDataProvider;
		private readonly IDateTimeProvider m_dateTimeProvider;
		private readonly TimeSpan m_keyLifetime;
		private readonly TimeSpan m_keyRotationPeriod;
		private readonly SemaphoreSlim m_privateKeyLock = new SemaphoreSlim( initialCount: 1 );

		private PrivateKey m_privateKey;
		
		public PrivateKeyProvider(
			IPublicKeyDataProvider publicKeyDataProvider,
			IDateTimeProvider dateTimeProvider,
			TimeSpan keyLifetime,
			TimeSpan keyRotationPeriod
		) {
			m_publicKeyDataProvider = publicKeyDataProvider;
			m_dateTimeProvider = dateTimeProvider;
			m_keyLifetime = keyLifetime;
			m_keyRotationPeriod = keyRotationPeriod;
		}

		private bool NeedFreshPrivateKey( PrivateKey key ) {
			return key == null || m_dateTimeProvider.UtcNow >= key.ValidTo - m_keyRotationPeriod;
		}
		
		async Task<D2LSecurityToken> IPrivateKeyProvider.GetSigningCredentialsAsync() {

			// Hold a local reference so that we know we are talking about the same key
			// after even if another thread changed m_privateKey (race condition when we
			// are using a key very close to the rotation time.)
			PrivateKey privateKey = m_privateKey;
			
			if( NeedFreshPrivateKey( privateKey ) ) {
				await m_privateKeyLock.WaitAsync().SafeAsync();
				try {
					privateKey = m_privateKey;

					if( NeedFreshPrivateKey( privateKey ) ) {
						m_privateKey = await CreatePrivateKeyAsync().SafeAsync();
						privateKey = m_privateKey;
					}

				} finally {
					m_privateKeyLock.Release();
				}
			}

			var csp = new RSACryptoServiceProvider( 2048 ) {
				PersistKeyInCsp = false
			};

			csp.ImportParameters( privateKey.RsaParameters );
			var rsaSecurityKey = new RsaSecurityKey( csp );

			return new D2LSecurityToken(
				privateKey.Id,
				privateKey.ValidFrom,
				privateKey.ValidTo,
				rsaSecurityKey );
		}

		private async Task<PrivateKey> CreatePrivateKeyAsync() {
			DateTime now = m_dateTimeProvider.UtcNow;
			DateTime expiresAt = now + m_keyLifetime;
			using( RSACryptoServiceProvider csp = new RSACryptoServiceProvider( 2048 ) ) {
				csp.PersistKeyInCsp = false;

				RSAParameters publicKey = csp.ExportParameters( includePrivateParameters: false );
				RSAParameters privateKey = csp.ExportParameters( includePrivateParameters: true );

				Guid keyId = Guid.NewGuid();

				var jwk = new RsaJsonWebKey( keyId, expiresAt, publicKey );

				await m_publicKeyDataProvider.SaveAsync( jwk ).SafeAsync();

				return new PrivateKey( keyId, privateKey, now, expiresAt );
			}
		}

		internal sealed class PrivateKey {
			private readonly Guid m_id;
			private readonly RSAParameters m_rsaParameters;
			private readonly DateTime m_validFrom;
			private readonly DateTime m_validTo;

			public PrivateKey(
				Guid id,
				RSAParameters rsaParameters,
				DateTime validFrom,
				DateTime validTo
			) {
				m_id = id;
				m_rsaParameters = rsaParameters;
				m_validFrom = validFrom;
				m_validTo = validTo;
			}

			public Guid Id {
				get { return m_id; }
			}

			public RSAParameters RsaParameters {
				get { return m_rsaParameters; }
			}

			public DateTime ValidFrom {
				get { return m_validFrom; }
			}

			public DateTime ValidTo {
				get { return m_validTo; }
			}
		}
	}
}
