using System;
using D2L.Security.OAuth2.Keys.Default;

namespace D2L.Security.OAuth2.Keys.Caching {
	internal interface IInMemoryPublicKeyCache {

		void Set( string srcNamespace, D2LSecurityKey key );
		D2LSecurityKey Get( string srcNamespace, Guid keyId );

	}
}
