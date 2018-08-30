using System;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Caching;
using D2L.Security.OAuth2.Keys.Default.Data;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class RemotePublicKeyProvider : IPublicKeyProvider {
		private readonly IJwksProvider m_jwksProvider;
		private readonly IInMemoryPublicKeyCache m_cache;

		public RemotePublicKeyProvider(
			IJwksProvider jwksProvider,
			IInMemoryPublicKeyCache cache
		) {
			m_jwksProvider = jwksProvider;
			m_cache = cache;
		}

		async Task<D2LSecurityToken> IPublicKeyProvider.GetByIdAsync( Guid id ) {
			D2LSecurityToken result = m_cache.Get( m_jwksProvider.Namespace, id );
			if( result != null ) {
				return result;
			}

			JsonWebKeySet jwks = await m_jwksProvider
				.RequestJwkAsync( id )
				.SafeAsync();

			CacheJwks( m_cache, m_jwksProvider.Namespace, jwks );

			result = m_cache.Get( m_jwksProvider.Namespace, id );
			if( result != null ) {
				return result;
			}

			throw new PublicKeyNotFoundException( id, jwks.Source.AbsoluteUri );
		}

		private static void CacheJwks( IInMemoryPublicKeyCache cache, string srcNamespace, JsonWebKeySet jwks ) {
			foreach( var jwk in jwks ) {
				D2LSecurityToken token;
				try {
					token = jwk.ToSecurityToken();
				} catch {
					continue;
				}

				cache.Set( srcNamespace, token );
			}
		}
	}
}
