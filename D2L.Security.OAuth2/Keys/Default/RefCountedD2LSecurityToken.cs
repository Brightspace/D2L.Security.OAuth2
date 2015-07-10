using System;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading;

namespace D2L.Security.OAuth2.Keys.Default {

	/// <summary>
	/// This class provides safety for private keys when used near key rotation time.
	/// By counting references, consumers of the <see cref="IPrivateKeyProvider"/> (strictly 
	/// an <see cref="ITokenSigner"/>) can use the D2LSecurityToken without having the resources
	/// disposed under them, and can properly "Dispose" it as they should without effecting other
	/// consumers / threads.
	/// </summary>
	internal sealed class RefCountedD2LSecurityToken : D2LSecurityToken, IDisposable {

		private readonly object m_disposeLock = new Object();
		private readonly D2LSecurityToken m_inner;

		private int m_refs = 0;
		private bool m_disposed = false;

		public RefCountedD2LSecurityToken(
			D2LSecurityToken inner
		) {
			m_inner = inner;

			Ref();
		}

		public RefCountedD2LSecurityToken Ref() {
			Interlocked.Increment( ref m_refs );
			return this;
		}

		public override void Dispose() {
			Interlocked.Decrement( ref m_refs );

			if( ShouldDispose() ) {
				lock( m_disposeLock ) {
					if( ShouldDispose() ) {
						m_disposed = true;
						m_inner.Dispose();
					}
				}
			}
		}

		private bool ShouldDispose() {
			return m_refs <= 0 && !m_disposed;
		}

		// Pass through to inner

		public override bool CanCreateKeyIdentifierClause<T>() {
			return m_inner.CanCreateKeyIdentifierClause<T>();
		}

		public override T CreateKeyIdentifierClause<T>() {
			return m_inner.CreateKeyIdentifierClause<T>();
		}

		public override AsymmetricAlgorithm GetAsymmetricAlgorithm() {
			return m_inner.GetAsymmetricAlgorithm();
		}

		public override SigningCredentials GetSigningCredentials() {
			return m_inner.GetSigningCredentials();
		}

		public override bool HasPrivateKey {
			get {
				return m_inner.HasPrivateKey;
			}
		}

		public override string Id {
			get {
				return m_inner.Id;
			}
		}

		public override Guid KeyId {
			get {
				return m_inner.KeyId;
			}
		}

		public override bool MatchesKeyIdentifierClause( SecurityKeyIdentifierClause keyIdentifierClause ) {
			return m_inner.MatchesKeyIdentifierClause( keyIdentifierClause );
		}

		public override SecurityKey ResolveKeyIdentifierClause( SecurityKeyIdentifierClause keyIdentifierClause ) {
			return m_inner.ResolveKeyIdentifierClause( keyIdentifierClause );
		}

		public override ReadOnlyCollection<SecurityKey> SecurityKeys {
			get {
				return m_inner.SecurityKeys;
			}
		}

		public override JsonWebKey ToJsonWebKey( bool includePrivateParameters = false ) {
			return m_inner.ToJsonWebKey( includePrivateParameters );
		}

		public override DateTime ValidFrom {
			get {
				return m_inner.ValidFrom;
			}
		}

		public override DateTime ValidTo {
			get {
				return m_inner.ValidTo;
			}
		}
	}
}
