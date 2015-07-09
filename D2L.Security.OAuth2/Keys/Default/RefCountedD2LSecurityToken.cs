using System;
using System.IdentityModel.Tokens;
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

		private int m_refs = 0;
		private bool m_disposed = false;

		public RefCountedD2LSecurityToken(
			Guid id,
			DateTime validFrom,
			DateTime validTo,
			Func<AsymmetricSecurityKey> keyFactory
		) : base(
			id: id,
			validFrom: validFrom,
			validTo: validTo,
			keyFactory: keyFactory
		) {
			Interlocked.Increment( ref m_refs );
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
						base.Dispose();
					}
				}
			}
		}

		private bool ShouldDispose() {
			return m_refs <= 0 && !m_disposed;
		}
	}
}
