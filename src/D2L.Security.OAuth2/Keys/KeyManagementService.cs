using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys {
	public sealed partial class KeyManagementService : IKeyManagementService, IPrivateKeyProvider, IDisposable {
		private readonly IPublicKeyDataProvider m_publicKeys;
		private readonly IPrivateKeyDataProvider m_privateKeys;
		private readonly IDateTimeProvider m_clock;
		private readonly OAuth2Configuration m_config;

		private D2LSecurityToken m_current = null;

		internal KeyManagementService(
			IPublicKeyDataProvider publicKeys,
			IPrivateKeyDataProvider privateKeys,
			IDateTimeProvider clock,
			OAuth2Configuration config
		) {
			m_publicKeys = publicKeys;
			m_privateKeys = privateKeys;
			m_clock = clock;
			m_config = config;
		}

		// Constructor for use outside of this library.
		// We are hiding our mockable clock interface for now, but we could
		// re-evaluate that in the future.
		public KeyManagementService(
			IPublicKeyDataProvider publicKeys,
			IPrivateKeyDataProvider privateKeys,
			OAuth2Configuration config = null
		) : this(
			publicKeys,
			privateKeys,
			new DateTimeProvider(),
			config ?? new OAuth2Configuration()
		) {
			config.CheckSanity();
		}

		[GenerateSync]
		async Task<D2LSecurityToken> IPrivateKeyProvider.GetSigningCredentialsAsync() {
			var current = Volatile.Read( ref m_current );

			var now = m_clock.UtcNow;

			if ( current == null || ExpectedTimeOfNewUsableKey( current ) < now ) {
				// Slow path: RefreshKeyAsync() wasn't called on boot and/or it
				// isn't being called in a background job.
				await RefreshKeyAsync( now )
					.ConfigureAwait( false );

				current = Volatile.Read( ref m_current );
			}

			if( current == null ) {
				return null;
			}

			return current.Ref();
		}

		private DateTimeOffset ExpectedTimeOfNewUsableKey( D2LSecurityToken current )
			// A new key will get generated some time before the current key
			// expires, but will only become usable some time after that.
			=> current.ValidTo
				- m_config.KeyRotationBuffer
				+ m_config.KeyTimeUntilUse;

		[GenerateSync]
		async Task<TimeSpan> IKeyManagementService.RefreshKeyAsync() {
			var now = m_clock.UtcNow;

			await RefreshKeyAsync( now )
				.ConfigureAwait( false );

			var current = Volatile.Read( ref m_current );

			if( current == null || now > current.ValidTo ) {
				// If the key is expired or doesn't exist, retry quickly.
				return TimeSpan.FromSeconds( 10 );
			}

			var expectedTimeOfNewUsableKey = ExpectedTimeOfNewUsableKey( current );

			if( now > expectedTimeOfNewUsableKey ) {
				// If we would have expected a new key by now, retry again in a
				// bit. This code branch supports configuration changes mostly.
				return TimeSpan.FromMinutes( 1 );
			} else {
				// Otherwise use that but with a little buffer for key
				// generation time/imprecisely scheduled cron jobs.
				return expectedTimeOfNewUsableKey.AddMinutes( 1 ) - now;
			}
		}

		async Task IKeyManagementService.GenerateNewKeyIfNeededAsync() {
			var now = m_clock.UtcNow;

			var keys = await m_privateKeys.GetAllAsync(
				validUntilAtLeast: now
			).ConfigureAwait( false );

			foreach( var key in keys ) {
				if( !key.WouldPreferToRotate( now, m_config.KeyRotationBuffer ) ) {
					// Found a suitable key, so we don't need to generate a new one.
					return;
				}
			}

			var keyId = Guid.NewGuid();
			var keyIdStr = keyId.ToString();

			using var csp = new RSACryptoServiceProvider( Constants.GENERATED_RSA_KEY_SIZE ) {
				PersistKeyInCsp = false
			};


			var pub = csp.ExportParameters(
				includePrivateParameters: false
			);

			var priv = csp.ExportCspBlob(
				includePrivateParameters: true
			);

			var expiresAt = now + m_config.KeyLifetime;

			await Task.WhenAll(
				m_publicKeys.SaveAsync(
					keyId,
					new RsaJsonWebKey(
						keyIdStr,
						expiresAt,
						pub
					)
				),
				m_privateKeys.SaveAsync(
					new PrivateKeyData(
						id: keyIdStr,
						kind: PrivateKeyData.KeyKinds.Rsa,
						data: priv,
						createdAt: now,
						notBefore: now + m_config.KeyTimeUntilUse,
						expiresAt: expiresAt
					)
				)
			).ConfigureAwait( false );
		}

		[GenerateSync]
		private async Task RefreshKeyAsync( DateTimeOffset now ) {
			var keys = await m_privateKeys.GetAllAsync(
				validUntilAtLeast: now
			).ConfigureAwait( false );

			var best = ChooseKey( keys, now )?.Ref();

			if( best == null ) {
				// If we didn't find anything in the database, continue with
				// the one we have (if any)
				return;
			}

			var prev = Interlocked.Exchange( ref m_current, best );

			prev?.Dispose();
		}

		private D2LSecurityToken ChooseKey(
			IEnumerable<PrivateKeyData> keys,
			DateTimeOffset now
		) {
			PrivateKeyData candidate = null;

			foreach( var key in keys ) {
				// Ignore unsupported key types
				if( key.Kind != PrivateKeyData.KeyKinds.Rsa ) {
					continue;
				}

				// The data provider should filter expired keys, but we don't
				// rely on that just in case.
				if( key.IsExpired( now ) ) {
					continue;
				}

				// Use any non-expired key if it's the only one
				if( candidate == null ) {
					candidate = key;
					continue;
				}

				var candidateIsPastNotBefore = candidate.IsPastNotBefore( now );
				var keyIsPastNotBefore = key.IsPastNotBefore( now );

				if( !candidateIsPastNotBefore && keyIsPastNotBefore ) {
					// Prefer keys past their "NotBefore" date because they are
					// guarunteed to not be excluded from caches.
					candidate = key;
				} else if( !candidateIsPastNotBefore && key.CreatedAt < candidate.CreatedAt ) {
					// When comparing two keys that are not past their NotBefore
					// points, prefer the oldest one (same cache rationale.)
					candidate = key;
				} else if( candidateIsPastNotBefore && keyIsPastNotBefore && candidate.CreatedAt < key.CreatedAt ) {
					// If we have two keys past their NotBefore date, pick the
					// one that was created most recently.
					candidate = key;
				}
			}

			if( candidate == null ) {
				return null;
			}

			Func<Tuple<AsymmetricSecurityKey, IDisposable>> keyFactory = candidate.Kind switch {
				PrivateKeyData.KeyKinds.Rsa => () => {
					var csp = new RSACryptoServiceProvider {
						PersistKeyInCsp = false
					};

					csp.ImportCspBlob( candidate.Data );

					var key = new RsaSecurityKey( csp );

					return new(key, csp);
				},
				_ => throw new NotImplementedException()
			};

			return new D2LSecurityToken(
				id: candidate.Id,
				validFrom: candidate.CreatedAt,
				validTo: candidate.ExpiresAt,
				keyFactory
			);
		}

		public void Dispose() {
			m_current?.Dispose();
		}
	}
}
