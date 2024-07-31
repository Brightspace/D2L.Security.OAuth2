namespace D2L.Security.OAuth2.Keys.Caching {
	internal sealed partial class InMemoryPublicKeyCache {
		private const string CACHE_KEY_PATTERN = "D2L.Security.OAuth2_PublicKeyCache_{0}_{1}";

		private static string BuildCacheKey( string srcNamespace, string keyId ) {
			string result = string.Format( CACHE_KEY_PATTERN, srcNamespace, keyId );
			return result;
		}
	}
}
