using System;
using System.Runtime.Caching;
using D2L.Security.OAuth2.Keys.Default;

namespace D2L.Security.OAuth2.Keys.Caching {
	internal sealed class InMemoryPublicKeyCache : IInMemoryPublicKeyCache {

		private const string CACHE_PREFIX = "D2L.Security.OAuth2_PublicKeyCache_";

		private readonly MemoryCache m_cache;

		public InMemoryPublicKeyCache() : this( MemoryCache.Default ) { }

		public InMemoryPublicKeyCache(
			MemoryCache cache
		) {
			if( cache == null ) {
				throw new ArgumentNullException( "cache" );
			}

			m_cache = cache;
		}

		void IInMemoryPublicKeyCache.Set( D2LSecurityToken key ) {
			m_cache.Set(
				BuildCacheKey( key.KeyId ),
				key,
				new CacheItemPolicy() {
					AbsoluteExpiration = key.ValidTo
				}
			);
		}

		D2LSecurityToken IInMemoryPublicKeyCache.Get( Guid keyId ) {
			var result = m_cache.Get( BuildCacheKey( keyId ) ) as D2LSecurityToken;
			return result;
		}

		private static string BuildCacheKey( Guid keyId ) {
			string result = CACHE_PREFIX + keyId;
			return result;
		}

	}
}
