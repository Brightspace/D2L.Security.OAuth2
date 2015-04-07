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
	internal sealed class LocalPrivateKeySecurityTokenManager : ISecurityTokenManager, IDisposable {
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

		Task<IEnumerable<D2LSecurityToken>> ISecurityTokenManager.GetAllTokens() {
			return m_inner.GetAllTokens();
		}

		Task ISecurityTokenManager.DeleteAsync( Guid id ) {
			if( m_securityToken.KeyId != id ) {
				return m_inner.DeleteAsync( id );
			}

			m_securityToken.Dispose();
			m_securityToken = null;
			return m_inner.DeleteAsync( id );
		}

		Task ISecurityTokenManager.SaveAsync( D2LSecurityToken token ) {
			if( !token.HasPrivateKey() ) {
				throw new InvalidOperationException(
					"Saving tokens without private keys is not supported by this implementation of ISecurityTokenManager" );
			}

			if( m_securityToken != null && token.ValidTo < m_securityToken.ValidTo ) {
				throw new InvalidOperationException(
					"Saving tokens that expires before the currently stored token is not supported by this implementation of ISecurityTokenManager" );
			}

			if( m_securityToken != null ) {
				m_securityToken.Dispose();
			}

			m_securityToken = token;

			return m_inner.SaveAsync( token );
		}

		public void Dispose() {
			if( m_securityToken != null ) {
				m_securityToken.Dispose();
			}
		}
	}
}
