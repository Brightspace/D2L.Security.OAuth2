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
		private readonly bool m_savePrivateBits;

		private readonly SemaphoreSlim m_privateKeyLock = new SemaphoreSlim( initialCount: 1 );

		private PrivateKey m_privateKey;

		public PrivateKeyProvider(
			IPublicKeyDataProvider publicKeyDataProvider,
			IDateTimeProvider dateTimeProvider,
			TimeSpan keyLifetime,
			TimeSpan keyRotationPeriod,
			bool savePrivateBits = false // TODO: this is for LMS 10.5.1. Remove this option for 10.5.2+
		) {
			m_publicKeyDataProvider = publicKeyDataProvider;
			m_dateTimeProvider = dateTimeProvider;
			m_keyLifetime = keyLifetime;
			m_keyRotationPeriod = keyRotationPeriod;
			m_savePrivateBits = savePrivateBits;
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
						DelayDisposeOfRsaSecurityKey( m_privateKey );
						m_privateKey = await CreatePrivateKeyAsync().SafeAsync();
						privateKey = m_privateKey;
					}

				} finally {
					m_privateKeyLock.Release();
				}
			}

			return new D2LSecurityToken(
				privateKey.Id,
				privateKey.ValidFrom,
				privateKey.ValidTo,
				privateKey.RsaSecurityKey
				);
		}

		private void DelayDisposeOfRsaSecurityKey( PrivateKey privateKey ) {

			// If no key has been assigned before, this will be null, so just return.
			if( privateKey == null ) {
				return;
			}

			// After a period of time, dispose of the key. The generous delay ensures any in-flight 
			// requests have time to finish.
			Task.Delay( TimeSpan.FromSeconds( 5 ) )
				.ContinueWith( t => privateKey.Dispose() );
		}

		private async Task<PrivateKey> CreatePrivateKeyAsync() {
			DateTime now = m_dateTimeProvider.UtcNow;
			DateTime expiresAt = now + m_keyLifetime;
			using( RSACryptoServiceProvider csp = new RSACryptoServiceProvider( Constants.KEY_SIZE ) ) {
				csp.PersistKeyInCsp = false;

				// TODO: remove m_savePrivateBits hack after 10.5.1!
				RSAParameters publicKey = csp.ExportParameters( includePrivateParameters: m_savePrivateBits );

				RSAParameters privateKey = csp.ExportParameters( includePrivateParameters: true );

				Guid keyId = Guid.NewGuid();

				var jwk = new RsaJsonWebKey( keyId, expiresAt, publicKey );

				await m_publicKeyDataProvider.SaveAsync( jwk ).SafeAsync();

				return new PrivateKey( keyId, privateKey, now, expiresAt );
			}
		}

		internal sealed class PrivateKey : IDisposable {
			private readonly Guid m_id;
			private readonly DateTime m_validFrom;
			private readonly DateTime m_validTo;
			private readonly RsaSecurityKey m_rsaSecurityKey;
			private readonly RSACryptoServiceProvider m_rsaCryptoServiceProvider;

			public PrivateKey(
				Guid id,
				RSAParameters privateKey,
				DateTime validFrom,
				DateTime validTo
			) {
				m_id = id;
				m_validFrom = validFrom;
				m_validTo = validTo;

				m_rsaCryptoServiceProvider = new RSACryptoServiceProvider( Constants.KEY_SIZE ) {
					PersistKeyInCsp = false
				};
				m_rsaCryptoServiceProvider.ImportParameters( privateKey );

				m_rsaSecurityKey = new RsaSecurityKey( m_rsaCryptoServiceProvider );
			}

			public Guid Id {
				get { return m_id; }
			}

			public DateTime ValidFrom {
				get { return m_validFrom; }
			}

			public DateTime ValidTo {
				get { return m_validTo; }
			}

			public RsaSecurityKey RsaSecurityKey {
				get { return m_rsaSecurityKey; }
			}

			public void Dispose() {
				m_rsaCryptoServiceProvider.Dispose();
			}
		}
	}
}
