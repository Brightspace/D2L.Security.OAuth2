using System;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Remote {
	internal interface IPublicKeyProvider {
		Task<D2LSecurityToken> GetSecurityTokenAsync( Uri jwksEndPoint, Guid keyId );
	}
}
