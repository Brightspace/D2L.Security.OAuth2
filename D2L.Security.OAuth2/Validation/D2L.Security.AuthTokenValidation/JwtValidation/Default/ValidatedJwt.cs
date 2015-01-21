using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace D2L.Security.AuthTokenValidation.JwtValidation {

	internal sealed class ValidatedJwt : IValidatedJwt {

		private readonly JwtSecurityToken m_inner;

		internal ValidatedJwt( JwtSecurityToken jwtSecurityToken ) {
			m_inner = jwtSecurityToken;
		}

		IEnumerable<Claim> IValidatedJwt.Claims {
			get { return m_inner.Claims; }
		}

		DateTime IValidatedJwt.Expiry {
			get { return m_inner.ValidTo; }
		}
	}
}
