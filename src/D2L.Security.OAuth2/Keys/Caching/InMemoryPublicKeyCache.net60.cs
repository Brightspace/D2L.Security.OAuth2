using System;
using D2L.CodeStyle.Annotations;
using D2L.Security.OAuth2.Keys.Default;
using Microsoft.Extensions.Caching.Memory;

namespace D2L.Security.OAuth2.Keys.Caching {
	internal sealed partial class InMemoryPublicKeyCache : IInMemoryPublicKeyCache {
		[Statics.Audited(
			owner: "Jacob Parker",
			auditedDate: "2021-01-27",
			rationale: "This is mutable but it's up to users currently to deal with this appropriately (e.g. use srcNamespace to segregate tenants) or use the constructor which doesn't use this global cache."
		)]
		private static readonly Lazy<IMemoryCache> m_globalCache
			= new Lazy<IMemoryCache>(
				() => new MemoryCache( new MemoryCacheOptions() )
			);

		private readonly IMemoryCache m_cache;

		public InMemoryPublicKeyCache() : this( m_globalCache.Value ) { }

		public InMemoryPublicKeyCache( IMemoryCache cache ) {
			m_cache = cache ?? throw new ArgumentNullException( nameof( cache ) );
		}

		void IInMemoryPublicKeyCache.Set( string srcNamespace, D2LSecurityToken key ) {
			MemoryCacheEntryOptions options = new MemoryCacheEntryOptions {
				AbsoluteExpiration = key.ValidTo,
			};
			options.RegisterPostEvictionCallback( EvictionCallback );

			m_cache.Set(
				key: BuildCacheKey( srcNamespace, key.KeyId ),
				value: key.Ref(),
				options: options
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

		private static void EvictionCallback( object key, object value, EvictionReason reason, object state ) {
			if( value is not D2LSecurityToken securityKey ) {
				return;
			}

			securityKey.Dispose();
		}
	}
}
