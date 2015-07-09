using System;
using D2L.Security.OAuth2.Keys.Default;

namespace D2L.Security.OAuth2.Keys.Caching {
	internal interface IInMemoryPublicKeyCache {

		void Set( D2LSecurityToken key );
		D2LSecurityToken Get( Guid keyId );

	}
}
