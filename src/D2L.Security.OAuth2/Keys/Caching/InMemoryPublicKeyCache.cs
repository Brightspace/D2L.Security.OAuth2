using System;
using System.Runtime.Caching;
using D2L.Security.OAuth2.Keys.Default;

namespace D2L.Security.OAuth2.Keys.Caching {
	internal sealed class InMemoryPublicKeyCache : IInMemoryPublicKeyCache {

		private const string CACHE_KEY_PATTERN = "D2L.Security.OAuth2_PublicKeyCache_{0}_{1}";

		private readonly MemoryCache m_cache;

		public InMemoryPublicKeyCache() : this( MemoryCache.Default ) { }

		public InMemoryPublicKeyCache(
			MemoryCache cache
		) {
			m_cache = cache ?? throw new ArgumentNullException( nameof( cache ) );
		}

		void IInMemoryPublicKeyCache.Set( string srcNamespace, D2LSecurityKey key ) {
			m_cache.Set(
				BuildCacheKey( srcNamespace, key.Id ),
				key,
				new CacheItemPolicy() {
					AbsoluteExpiration = key.ValidTo
				}
			);
		}

		D2LSecurityKey IInMemoryPublicKeyCache.Get( string srcNamespace, Guid keyId ) {
			var result = m_cache.Get( BuildCacheKey( srcNamespace, keyId ) ) as D2LSecurityKey;
			return result;
		}

		private static string BuildCacheKey( string srcNamespace, Guid keyId ) {
			string result = string.Format( CACHE_KEY_PATTERN, srcNamespace, keyId );
			return result;
		}

	}
}
