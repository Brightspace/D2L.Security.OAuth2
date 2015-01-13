using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace D2L.Security.AuthTokenValidation.TokenValidation {

	internal sealed class ValidatedJWT : IValidatedJWT {

		private readonly JwtSecurityToken m_inner;

		internal ValidatedJWT( JwtSecurityToken jwtSecurityToken ) {
			m_inner = jwtSecurityToken;
		}

		IEnumerable<Claim> IValidatedJWT.Claims {
			get { return m_inner.Claims; }
		}

		DateTime IValidatedJWT.Expiry {
			get { return m_inner.ValidTo; }
		}
	}
}
