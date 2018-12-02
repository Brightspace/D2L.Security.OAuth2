using System;
using System.Threading;

namespace D2L.Security.OAuth2.Keys.Default {

	/// <summary>
	/// This portion of the class class provides safety for private keys when used near key rotation time.
	/// By counting references, consumers of the <see cref="IPrivateKeyProvider"/> (strictly
	/// an <see cref="ITokenSigner"/>) can use the D2LSecurityToken without having the resources
	/// disposed under them, and can properly "Dispose" it as they should without effecting other
	/// consumers / threads.
	/// </summary>
	internal partial class D2LSecurityToken : IDisposable {

		private readonly object m_disposeLock = new Object();

		private bool m_disposed = false;
		private int m_refCount = 0;

		internal D2LSecurityToken Ref() {
			Interlocked.Increment( ref m_refCount );

			return this;
		}

		public void Dispose() {
			Interlocked.Decrement( ref m_refCount );

			if( ShouldDispose() ) {
				lock( m_disposeLock ) {
					if( ShouldDispose() ) {
						m_disposed = true;

						foreach( var key in m_key.Values ) {
							var disposable = key.Item2;
							if( disposable != null ) {
								disposable.Dispose();
							}
						}

						m_key.Dispose();
					}
				}
			}
		}

		private bool ShouldDispose() {
			return m_refCount <= 0 && !m_disposed;
		}

	}
}
