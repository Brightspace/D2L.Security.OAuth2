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
			m_publicKeyDataProvider = publicKeyDataProvider ?? throw new ArgumentNullException( nameof( publicKeyDataProvider ) );
			m_cache = cache ?? throw new ArgumentNullException( nameof( cache ) );
		}

		async Task<D2LSecurityToken> IPublicKeyProvider.GetByIdAsync( string id ) {
			D2LSecurityToken result = m_cache.Get( PUBLIC_KEY_SOURCE, id );
			if( result != null ) {
				return result;
			}

			JsonWebKey jwk = await m_publicKeyDataProvider
				.GetByIdAsync( new Guid( id ) )
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
