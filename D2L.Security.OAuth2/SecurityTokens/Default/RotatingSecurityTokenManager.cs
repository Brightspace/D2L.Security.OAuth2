using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.SecurityTokens.Default {
	public sealed class RotatingSecurityTokenManager : ISecurityTokenManager {
		private readonly ISecurityTokenManager m_inner;
		private readonly ISecurityTokenFactory m_securityTokenFactory;
		private readonly TimeSpan m_rotationBuffer;
		private readonly TimeSpan m_tokenLifetime;

		public static readonly TimeSpan DEFAULT_ROTATION_BUFFER
			= TimeSpan.FromMinutes( 10 );

		public static readonly TimeSpan DEFAULT_TOKEN_LIFETIME
			= TimeSpan.FromHours( 1 );

		/// <summary>
		/// Callers should prefer this constructor because it uses a
		/// pre-configured rotation buffer. If all you are doing is the JWT
		/// bearer token grant then your SecurityTokens don't need to live long
		/// and you should use the value chosen by this library.
		/// </summary>
		public RotatingSecurityTokenManager(
			ISecurityTokenManager inner,
			ISecurityTokenFactory securityTokenFactory
		) : this( inner, securityTokenFactory, DEFAULT_ROTATION_BUFFER, DEFAULT_TOKEN_LIFETIME ) { }

		/// <summary>
		/// Do not use this overload unless you need to customize the token
		/// rotation buffer and lifetimes.
		/// </summary>
		public RotatingSecurityTokenManager(
			ISecurityTokenManager inner,
			ISecurityTokenFactory securityTokenFactory,
			TimeSpan rotationBuffer,
			TimeSpan tokenLifetime
		) {
			m_inner = inner;
			m_securityTokenFactory = securityTokenFactory;
			m_rotationBuffer = rotationBuffer;
			m_tokenLifetime = tokenLifetime;
		}

		async Task<D2LSecurityToken> ISecurityTokenManager.GetLatestTokenAsync() {
			D2LSecurityToken token = await m_inner.GetLatestTokenAsync();

			if( token != null ) {
				if( !token.HasPrivateKey() ) {
					throw new InvalidOperationException(
						"token from inner ISecurityTokenManager.GetLatestTokenAsync didn't contain a private key"
					);
				}

				if( !token.IsExpiringSoon( m_rotationBuffer ) ) {
					return token;
				}

				// We are eagerly flushing expired tokens here; not strictly
				// required.
				if( token.IsExpired() ) {
					m_inner.DeleteFireAndForget( token.KeyId );
				}
			}

			// At this point we either didn't get a token, it was expiring or
			// it was expired (and we deleted it.)

			token = m_securityTokenFactory.Create( m_tokenLifetime );

			// Wait for the token to be created: we do this so that we don't
			// use a token before its available via GetAllTokens().
			await m_inner.SaveAsync( token );

			return token;
		}

		/// <remarks>
		/// This implementation eagerly deletes expired tokens (but does not
		/// wait for deletion to complete) and never returns them to the
		/// caller.
		/// This implementation makes no garuntees about wether the security
		/// tokens it returns have their private key.
		/// </remarks>
		IEnumerable<D2LSecurityToken> ISecurityTokenManager.GetAllTokens() {
			// Immediately ToList() this to avoid any problems with invalid
			// iterators (depending on how m_inner is implemented, calling
			// Delete while iterating could be problematic.
			List<D2LSecurityToken> tokens = m_inner
				.GetAllTokens()
				.ToList();

			// Don't expose any expired tokens to the caller
			foreach( D2LSecurityToken token in tokens ) {
				if( token.IsExpired() ) {
					m_inner.DeleteFireAndForget( token.KeyId );
				} else {
					yield return token;
				}
			}
		}

		async Task ISecurityTokenManager.DeleteAsync( Guid id ) {
			await m_inner.DeleteAsync( id );
		}

		async Task ISecurityTokenManager.SaveAsync( D2LSecurityToken token ) {
			await m_inner.SaveAsync( token );
		}
	}
}
