using System;
using D2L.Security.OAuth2.Keys.Default;
using Microsoft.Extensions.Caching.Memory;

namespace D2L.Security.OAuth2.Keys.Caching {
	internal sealed partial class InMemoryPublicKeyCache : IInMemoryPublicKeyCache {
		private readonly IMemoryCache m_cache;

		public InMemoryPublicKeyCache() : this(
			new MemoryCache( new MemoryCacheOptions() ) ) {}

		public InMemoryPublicKeyCache( MemoryCache cache ) {
			m_cache = cache ?? throw new ArgumentNullException( nameof( cache ) );
		}

		void IInMemoryPublicKeyCache.Set( string srcNamespace, D2LSecurityToken key ) {
			m_cache.Set(
				key: BuildCacheKey( srcNamespace, key.KeyId ),
				value: key,
				new MemoryCacheEntryOptions {
					AbsoluteExpiration = key.ValidTo
				}
			);
		}

		D2LSecurityToken IInMemoryPublicKeyCache.Get( string srcNamespace, string keyId ) {
			var found = m_cache.TryGetValue(
				BuildCacheKey( srcNamespace, keyId ),
				out var key
			);

			if( !found ) {
				return null;
			}

			return key as D2LSecurityToken;
		}
	}
}
