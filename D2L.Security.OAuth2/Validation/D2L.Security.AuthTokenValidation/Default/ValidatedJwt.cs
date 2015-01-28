using System;
using System.Collections.Generic;
using System.Security.Claims;
using D2L.Security.AuthTokenValidation.JwtValidation;

namespace D2L.Security.AuthTokenValidation.Default {
	internal sealed class ValidatedJwtToValidatedTokenAdapter : IValidatedToken {

		private readonly IValidatedJwt m_inner;

		internal ValidatedJwtToValidatedTokenAdapter( IValidatedJwt inner ) {
			m_inner = inner;
		}

		IEnumerable<Claim> IValidatedToken.Claims {
			get { return m_inner.Claims; }
		}

		DateTime IValidatedToken.Expiry {
			get { return m_inner.Expiry; }
		}
	}
}
