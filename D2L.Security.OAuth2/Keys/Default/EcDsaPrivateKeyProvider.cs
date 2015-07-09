using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class EcDsaPrivateKeyProvider : IPrivateKeyProvider {

		private readonly IPublicKeyDataProvider m_publicKeyDataProvider;
		private readonly IDateTimeProvider m_dateTimeProvider;
		private readonly CngAlgorithm m_algorithm;
		private readonly TimeSpan m_keyLifetime;
		private readonly TimeSpan m_keyRotationPeriod;

		private readonly SemaphoreSlim m_privateKeyLock = new SemaphoreSlim( initialCount: 1 );

		private RefCountedD2LSecurityToken m_privateKey;

		public EcDsaPrivateKeyProvider(
			ISanePublicKeyDataProvider publicKeyDataProvider,
			IDateTimeProvider dateTimeProvider,
			CngAlgorithm algorithm,
			TimeSpan keyLifetime,
			TimeSpan keyRotationPeriod
		) {
			if( keyLifetime < keyRotationPeriod ) {
				throw new ArgumentException( "Private key lifetime must exceed the rotation period", "keyLifetime" );
			}

			m_publicKeyDataProvider = publicKeyDataProvider;
			m_dateTimeProvider = dateTimeProvider;
			m_algorithm = algorithm;
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

			var creationParams = new CngKeyCreationParameters() {
				ExportPolicy = CngExportPolicies.AllowPlaintextExport,
				KeyUsage = CngKeyUsages.Signing
			};

			byte[] publicBlob;
			byte[] privateBlob;
			using( var cngKey = CngKey.Create( m_algorithm, null, creationParams ) ) {
				using( ECDsaCng ecDsa = new ECDsaCng( cngKey ) ) {
					publicBlob = ecDsa.Key.Export( CngKeyBlobFormat.EccPublicBlob );
					privateBlob = ecDsa.Key.Export( CngKeyBlobFormat.EccPrivateBlob );
				}
			}

			Guid keyId = Guid.NewGuid();

			var jwk = new EcDsaJsonWebKey( keyId, expiresAt, publicBlob );

			await m_publicKeyDataProvider.SaveAsync( jwk ).SafeAsync();

			return new RefCountedD2LSecurityToken(
				id: keyId,
				validFrom: now,
				validTo: expiresAt,
				keyFactory: () => {
					using( var cng = CngKey.Import( privateBlob, CngKeyBlobFormat.EccPrivateBlob ) ) {
						// ECDsaCng copies the CngKey, hence the using
						var ecDsa = new ECDsaCng( cng );
						return new EcDsaSecurityKey( ecDsa );
					}
				}
			);
		}
	}
}