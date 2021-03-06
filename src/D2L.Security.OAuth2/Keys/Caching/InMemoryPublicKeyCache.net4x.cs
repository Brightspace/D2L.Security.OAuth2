﻿using System;
using System.Runtime.Caching;
using D2L.Security.OAuth2.Keys.Default;

namespace D2L.Security.OAuth2.Keys.Caching {
	internal sealed partial class InMemoryPublicKeyCache : IInMemoryPublicKeyCache {
		private readonly MemoryCache m_cache;

		public InMemoryPublicKeyCache() : this( MemoryCache.Default ) { }

		public InMemoryPublicKeyCache( MemoryCache cache ) {
			m_cache = cache ?? throw new ArgumentNullException( nameof( cache ) );
		}

		void IInMemoryPublicKeyCache.Set( string srcNamespace, D2LSecurityToken key ) {
			m_cache.Set(
				BuildCacheKey( srcNamespace, key.KeyId ),
				key,
				new CacheItemPolicy() {
					AbsoluteExpiration = key.ValidTo
				}
			);
		}

		D2LSecurityToken IInMemoryPublicKeyCache.Get( string srcNamespace, string keyId ) {
			var result = m_cache.Get( BuildCacheKey( srcNamespace, keyId ) ) as D2LSecurityToken;
			return result;
		}
	}
}
