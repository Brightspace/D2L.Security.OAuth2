using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Jwks;
using D2L.Security.OAuth2.Validation.Request.Core.Default;
using D2L.Security.OAuth2.Validation.Token;
using D2L.Security.OAuth2.Validation.Token.JwtValidation;

namespace D2L.Security.OAuth2.Validation {
	internal sealed class AccessTokenValidator : IAccessTokenValidator {

		private readonly ISecurityKeyProvider m_securityKeyProvider;
		private readonly JwtSecurityTokenHandler m_tokenHandler = new JwtSecurityTokenHandler();

		public AccessTokenValidator(
			ISecurityKeyProvider securityKeyProvider
		) {
			m_securityKeyProvider = securityKeyProvider;
		}

		async Task<ValidationResponse> IAccessTokenValidator.ValidateAsync(
			Uri jwksEndPoint,
			string token
		) {

			var unvalidatedToken = (JwtSecurityToken)m_tokenHandler.ReadToken(
				token
			);

			if( !unvalidatedToken.Header.ContainsKey( "kid" ) ) {
				throw new Exception( "KeyId not found in token" );
			}

			// TODO should this be ToString?
			var keyId = (string)unvalidatedToken.Header["kid"];

			SecurityKey securityKey = await m_securityKeyProvider.GetSecurityKeyAsync(
				jwksEndPoint: jwksEndPoint,
				keyId: keyId
			);
			
			// TODO ... do we validate audience, issuer, or anything else?
			var validationParameters = new TokenValidationParameters() {
				RequireSignedTokens = true,
				IssuerSigningKey = securityKey
			};
			
			IValidatedToken validatedToken = null;
			var status = ValidationStatus.Success;

			try {

				SecurityToken securityToken;
				m_tokenHandler.ValidateToken(
					token,
					validationParameters,
					out securityToken
				);
				validatedToken = new ValidatedJwt( (JwtSecurityToken)securityToken );

			} catch( SecurityTokenExpiredException ) {
				status = ValidationStatus.Expired;
			}

			return new ValidationResponse(
				status,
				validatedToken
			);

		}

	}
}
