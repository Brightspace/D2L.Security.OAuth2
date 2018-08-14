using System;
using System.IdentityModel.Tokens;
using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Keys.Default {

	[Immutable]
	internal interface ID2LSecurityTokenFactory {

		D2LSecurityToken Create( Func<Tuple<AsymmetricSecurityKey, IDisposable>> keyFactory );

	}
}
