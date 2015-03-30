using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.SecurityTokens.Default {
	/// <summary>
	/// An ISecurityTokenManager that keeps a single key locally in memory.
	/// </summary>
	/// <remarks>
	/// The inner ISecurityTokenManager for this implementation should only be
	/// saving public keys.
	///
	/// See the README.md for the detailed theory behind this class.
	/// </remarks>
	internal sealed class LocalPrivateKeySecurityTokenManager : ISecurityTokenManager {
		private readonly ISecurityTokenManager m_inner;
		private D2LSecurityToken m_securityToken;

		public LocalPrivateKeySecurityTokenManager(
			ISecurityTokenManager inner	
		) {
			m_inner = inner;
		}

		Task<D2LSecurityToken> ISecurityTokenManager.GetLatestTokenAsync() {
			return Task.FromResult( m_securityToken );
		}

		IEnumerable<D2LSecurityToken> ISecurityTokenManager.GetAllTokens() {
			return m_inner.GetAllTokens();
		}

		async Task ISecurityTokenManager.DeleteAsync( Guid id ) {
			if( m_securityToken.KeyId == id ) {
				m_securityToken.Dispose();
				m_securityToken = null;
			}
			await m_inner.DeleteAsync( id );
		}

		async Task ISecurityTokenManager.SaveAsync( D2LSecurityToken token ) {
			if( !token.HasPrivateKey() ) {
				throw new InvalidOperationException(
					"Saving tokens without private keys is not supported by this implementation of ISecurityTokenManager"
				);
			}
			if( m_securityToken != null && token.ValidTo < m_securityToken.ValidTo ) {
				throw new InvalidOperationException(
					"Saving tokens that expires before the currently stored token is not supported by this implementation of ISecurityTokenManager"
				);
			}
			m_securityToken = token;
			await m_inner.SaveAsync( token );
		}
	}
}
