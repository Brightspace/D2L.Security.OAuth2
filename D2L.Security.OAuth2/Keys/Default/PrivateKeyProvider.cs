using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class PrivateKeyProvider : IPrivateKeyProvider {

		private readonly IPublicKeyDataProvider m_publicKeyDataProvider;
		private readonly IDateTimeProvider m_dateTimeProvider;
		private readonly TimeSpan m_keyLifetime;
		private readonly TimeSpan m_keyRotationPeriod;

		private readonly SemaphoreSlim m_privateKeyLock = new SemaphoreSlim( initialCount: 1 );

		private RefCountedD2LSecurityToken m_privateKey;

		public PrivateKeyProvider(
			ISanePublicKeyDataProvider publicKeyDataProvider,
			IDateTimeProvider dateTimeProvider,
			TimeSpan keyLifetime,
			TimeSpan keyRotationPeriod
		) {
			if( keyLifetime < keyRotationPeriod ) {
				throw new ArgumentException( "Private key lifetime must exceed the rotation period", "keyLifetime" );
			}

			m_publicKeyDataProvider = publicKeyDataProvider;
			m_dateTimeProvider = dateTimeProvider;
			m_keyLifetime = keyLifetime;
			m_keyRotationPeriod = keyRotationPeriod;
		}
		
		async Task<D2LSecurityToken> IPrivateKeyProvider.GetSigningCredentialsAsync() {

			// Hold a local reference so that we know we are talking about the same key
			// after even if another thread changed m_privateKey (race condition when we
			// are using a key very close to the rotation time.)
			RefCountedD2LSecurityToken privateKey = m_privateKey;

			if( NeedFreshPrivateKey( privateKey ) ) {
				// This Semaphore is used instead of lock(foo){}
				// because await cannot be used within a lock
				await m_privateKeyLock.WaitAsync().SafeAsync();
				try {
					privateKey = m_privateKey;

					if( NeedFreshPrivateKey( privateKey ) ) {
						m_privateKey = await CreatePrivateKeyAsync().SafeAsync();

						if( privateKey != null ) {
							privateKey.Dispose();
						}

						privateKey = m_privateKey;
					}

				} finally {
					m_privateKeyLock.Release();
				}
			}

			return privateKey.Ref();
		}

		private bool NeedFreshPrivateKey( D2LSecurityToken key ) {
			return key == null || m_dateTimeProvider.UtcNow >= key.ValidTo - m_keyRotationPeriod;
		}

		private async Task<RefCountedD2LSecurityToken> CreatePrivateKeyAsync() {
			DateTime now = m_dateTimeProvider.UtcNow;
			DateTime expiresAt = now + m_keyLifetime;

			RSAParameters publicKey;
			RSAParameters privateKey;
			using( var csp = new RSACryptoServiceProvider( Constants.GENERATED_RSA_KEY_SIZE ) { PersistKeyInCsp = false } ) {
				publicKey = csp.ExportParameters( includePrivateParameters: false );
				privateKey = csp.ExportParameters( includePrivateParameters: true );
			}

			Guid keyId = Guid.NewGuid();

			var jwk = new RsaJsonWebKey( keyId, expiresAt, publicKey );

			await m_publicKeyDataProvider.SaveAsync( jwk ).SafeAsync();

			return new RefCountedD2LSecurityToken(
				id: keyId,
				validFrom: now,
				validTo: expiresAt,
				keyFactory: () => {
					var csp = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
					csp.ImportParameters( privateKey );
					var key = new RsaSecurityKey( csp );
					return key;
				}
			);
		}
	}
}
