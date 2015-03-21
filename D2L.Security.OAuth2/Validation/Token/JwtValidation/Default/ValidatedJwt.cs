using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace D2L.Security.OAuth2.Validation.Token.JwtValidation {

	internal sealed class ValidatedJwt : IValidatedToken {

		private readonly JwtSecurityToken m_inner;

		internal ValidatedJwt( JwtSecurityToken jwtSecurityToken ) {
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
