using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using D2L.CodeStyle.Annotations;
using static D2L.CodeStyle.Annotations.Objects;

#if DNXCORE50
using System.IdentityModel.Tokens.Jwt;
#endif

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	[Immutable]
	internal sealed class AccessToken : IAccessToken {
		[Mutability.Audited( "Todd Lang", "02-Mar-2018", ".Net class we can't modify, but is used immutably." )]
		private readonly JwtSecurityToken m_inner;
		private readonly IAccessToken m_this;

		internal AccessToken( JwtSecurityToken jwtSecurityToken ) {
			m_inner = jwtSecurityToken;
			m_this = this;
		}

		string IAccessToken.Id {
			get { return m_this.GetClaimValue( Constants.Claims.TOKEN_ID ); }
		}

		DateTime IAccessToken.Expiry {
			get { return m_inner.ValidTo; }
		}

		IEnumerable<Claim> IAccessToken.Claims {
			get { return m_inner.Claims; }
		}

		string IAccessToken.SensitiveRawAccessToken {
			get { return m_inner.RawData; }
		}
	}
}
