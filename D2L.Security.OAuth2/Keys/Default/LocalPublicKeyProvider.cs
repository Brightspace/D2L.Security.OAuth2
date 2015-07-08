using System;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Caching;
using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Keys.Default {

	internal sealed class LocalPublicKeyProvider : IPublicKeyProvider {

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
			D2LSecurityToken result = m_cache.Get( id );
			if( result != null ) {
				return result;
			}

			JsonWebKey jwk = await m_publicKeyDataProvider.GetByIdAsync( id );

			if( jwk != null ) {
				result = jwk.ToSecurityToken();
				m_cache.Set( result );
				return result;
			}

			throw new PublicKeyNotFoundException(
				string.Format( "Could not find public key with id '{0}'", id )
			);
		}
	}
}
