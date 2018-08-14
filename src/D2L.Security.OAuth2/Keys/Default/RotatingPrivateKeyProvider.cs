﻿using System;
using System.Threading;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Utilities;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class RotatingPrivateKeyProvider : IPrivateKeyProvider {

		private readonly IPrivateKeyProvider m_inner;
		private readonly IDateTimeProvider m_dateTimeProvider;
		private readonly TimeSpan m_keyRotationPeriod;

		[Mutability.Audited(
			"Todd Lang",
			"14-Aug-2018",
			".Net class we can't mark, used internally without mutability." )]
		private readonly SemaphoreSlim m_privateKeyLock = new SemaphoreSlim( initialCount: 1 );

		[Mutability.Audited(
			"Todd Lang",
			"14-Aug-2018",
			"Used internally, protected threaded access, no way to modify externally." )]
		private D2LSecurityToken m_privateKey;

		public RotatingPrivateKeyProvider(
			IPrivateKeyProvider inner,
			IDateTimeProvider dateTimeProvider,
			TimeSpan keyRotationPeriod
		) {
			m_inner = inner;
			m_dateTimeProvider = dateTimeProvider;
			m_keyRotationPeriod = keyRotationPeriod;
		}

		async Task<D2LSecurityToken> IPrivateKeyProvider.GetSigningCredentialsAsync() {

			// Hold a local reference so that we know we are talking about the same key
			// after even if another thread changed m_privateKey (race condition when we
			// are using a key very close to the rotation time.)
			D2LSecurityToken privateKey = m_privateKey;

			if( NeedFreshPrivateKey( privateKey ) ) {
				// This Semaphore is used instead of lock(foo){}
				// because await cannot be used within a lock
				await m_privateKeyLock.WaitAsync().SafeAsync();
				try {
					privateKey = m_privateKey;

					if( NeedFreshPrivateKey( privateKey ) ) {
						m_privateKey = ( await m_inner.GetSigningCredentialsAsync().SafeAsync() ).Ref();

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
	}
}