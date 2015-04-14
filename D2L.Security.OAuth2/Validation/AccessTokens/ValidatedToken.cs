using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace D2L.Security.OAuth2.Validation.AccessTokens {

	internal sealed class ValidatedToken : IValidatedToken {

		private readonly JwtSecurityToken m_inner;

		internal ValidatedToken( JwtSecurityToken jwtSecurityToken ) {
			m_inner = jwtSecurityToken;
		}

		IEnumerable<Claim> IValidatedToken.Claims {
			get { return m_inner.Claims; }
		}

		DateTime IValidatedToken.Expiry {
			get { return m_inner.ValidTo; }
		}
	}
}
