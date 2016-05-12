using System;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Caching;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class LocalPublicKeyProvider : IPublicKeyProvider {

		private const string PUBLIC_KEY_SOURCE = "Local DB";

		private readonly IPublicKeyDataProvider m_publicKeyDataProvider;
		private readonly IInMemoryPublicKeyCache m_cache;

		public LocalPublicKeyProvider(
			ISanePublicKeyDataProvider publicKeyDataProvider,
			IInMemoryPublicKeyCache cache
		) {
			if( publicKeyDataProvider == null ) {
				throw new ArgumentNullException( "publicKeyDataProvider" );
			}

			if( cache == null ) {
				throw new ArgumentNullException( "cache" );
			}

			m_publicKeyDataProvider = publicKeyDataProvider;
			m_cache = cache;
		}

		async Task<D2LSecurityToken> IPublicKeyProvider.GetByIdAsync( Guid id ) {
			D2LSecurityToken result = m_cache.Get( PUBLIC_KEY_SOURCE, id );
			if( result != null ) {
				return result;
			}

			JsonWebKey jwk = await m_publicKeyDataProvider
				.GetByIdAsync( id )
				.SafeAsync();

			if( jwk != null ) {
				result = jwk.ToSecurityToken();
				m_cache.Set( PUBLIC_KEY_SOURCE, result );
				return result;
			}

			throw new PublicKeyNotFoundException( id, PUBLIC_KEY_SOURCE );
		}
	}
}
