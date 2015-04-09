using System;

namespace D2L.Security.OAuth2.Caching {
	internal sealed class NullCache : ICache {

		bool ICache.TryGet( string key, out string value ) {
			value = default( string );
			return false;
		}

		void ICache.Set(
			string key,
			string value,
			TimeSpan expiry
		) { }

		void ICache.Remove( string key ) { }
	}
}
