using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Keys.Caching;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed partial class LocalPublicKeyProvider : IPublicKeyProvider {

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

		[GenerateSync]
		async Task IPublicKeyProvider.PrefetchAsync() {
			IEnumerable<JsonWebKey> jwks = await m_publicKeyDataProvider
				.GetAllAsync()
				.ConfigureAwait( false );

			foreach( JsonWebKey jwk in jwks ) {
				if( m_cache.Get( PUBLIC_KEY_SOURCE, jwk.Id ) is not null ) {
					continue;
				}

				D2LSecurityToken token;
				try {
					token = jwk.ToSecurityToken();
				} catch {
					continue;
				}

				m_cache.Set( PUBLIC_KEY_SOURCE, token );
			}
		}

		[GenerateSync]
		async Task<D2LSecurityToken> IPublicKeyProvider.GetByIdAsync( string id ) {
			D2LSecurityToken result = m_cache.Get( PUBLIC_KEY_SOURCE, id );
			if( result != null ) {
				return result;
			}

			JsonWebKey jwk = await m_publicKeyDataProvider
				.GetByIdAsync( new Guid( id ) )
				.ConfigureAwait( false );

			if( jwk != null ) {
				result = jwk.ToSecurityToken();
				m_cache.Set( PUBLIC_KEY_SOURCE, result );
				return result;
			}

			throw new PublicKeyNotFoundException( id, PUBLIC_KEY_SOURCE );
		}
	}
}
