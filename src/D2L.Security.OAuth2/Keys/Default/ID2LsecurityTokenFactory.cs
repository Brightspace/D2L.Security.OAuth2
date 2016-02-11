using System;
using System.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {
	internal interface ID2LSecurityTokenFactory {

		D2LSecurityToken Create( Func<Tuple<AsymmetricSecurityKey, IDisposable>> keyFactory );

	}
}
