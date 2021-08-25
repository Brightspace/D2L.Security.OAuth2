using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys {
	internal sealed class KeyManagementService : IKeyManagementService, IPrivateKeyProvider, IDisposable {
		private readonly IPublicKeyDataProvider m_publicKeys;
		private readonly IPrivateKeyDataProvider m_privateKeys;
		private readonly IDateTimeProvider m_clock;
		private readonly OAuth2Configuration m_config;

		private D2LSecurityToken m_current = null;

		public KeyManagementService(
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

		async Task<D2LSecurityToken> IPrivateKeyProvider.GetSigningCredentialsAsync() {
			var current = Volatile.Read( ref m_current );

			var now = m_clock.UtcNow;

			if ( current == null || current.ValidTo <= now ) {
				// Slow path: RefreshKeyAsync() wasn't called on boot and/or it
				// isn't being called in a background job.
				await RefreshKeyAsync( current, now )
					.ConfigureAwait( false );

				current = Volatile.Read( ref m_current );
			}

			return current.Ref();
		}

		async Task<TimeSpan> IKeyManagementService.RefreshKeyAsync() {
			var current = Volatile.Read( ref m_current );

			var now = m_clock.UtcNow;

			await RefreshKeyAsync(
				current,
				now
			).ConfigureAwait( false );

			current = Volatile.Read( ref m_current );

			var expectedNextRotation = current.ValidTo - m_config.KeyRotationBuffer;

			if( now > expectedNextRotation ) {
				// If that's in the past, use a short retry window.
				return TimeSpan.FromSeconds( 10 );
			} else {
				// Otherwise use that but with a little buffer for key
				// generation time/imprecisely scheduled cron jobs.
				return expectedNextRotation.AddMinutes( 1 ) - now;
			}
		}

		async Task IKeyManagementService.GenerateNewKeyIfNeededAsync() {
			var now = m_clock.UtcNow;

			var keys = await m_privateKeys.GetAllAsync(
				validUntilAtLeast: now
			).ConfigureAwait( false );

			foreach( var key in keys ) {
				if( now < key.ExpiresAt - m_config.KeyRotationBuffer ) {
					// This key is fine, do nothing.
					return;
				}
			}

			var keyId = Guid.NewGuid();
			var keyIdStr = keyId.ToString();

			using var csp = new RSACryptoServiceProvider {
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

		private async Task RefreshKeyAsync(
			D2LSecurityToken current,
			DateTimeOffset now
		) {
			var keys = await m_privateKeys.GetAllAsync(
				validUntilAtLeast: now
			).ConfigureAwait( continueOnCapturedContext: false );

			var best = ChooseKey( keys, now ).Ref();

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

				// Use any non-expired key if it's the only one
				if( candidate == null ) {
					candidate = key;
					continue;
				}

				if( candidate.NotBefore > now && key.NotBefore <= now ) {
					// If we can switch to a key past its NotBefore, do that.
					candidate = key;
				} else if( candidate.NotBefore > now && candidate.CreatedAt > key.CreatedAt ) {
					// When comparing two keys that are not past their respective
					// NotBefore points, prefer the oldest one.
					candidate = key;
				} else if ( candidate.NotBefore <= now && key.NotBefore <= now && candidate.CreatedAt < key.CreatedAt ) {
					// If we have two keys past their NotBefore date, pick the
					// one that was created most recently.
					candidate = key;
				}
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
