using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Jwks;
using D2L.Security.OAuth2.Validation.Token;
using D2L.Security.OAuth2.Validation.Token.JwtValidation;

namespace D2L.Security.OAuth2.Validation {
	internal sealed class AccessTokenValidator : IAccessTokenValidator {

		private readonly IPublicKeyProvider m_publicKeyProvider;
		private readonly JwtSecurityTokenHandler m_tokenHandler = new JwtSecurityTokenHandler();

		public AccessTokenValidator(
			IPublicKeyProvider publicKeyProvider
		) {
			m_publicKeyProvider = publicKeyProvider;
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

			SecurityToken signingToken = await m_publicKeyProvider.GetSecurityTokenAsync(
				jwksEndPoint: jwksEndPoint,
				keyId: keyId
			).ConfigureAwait( false );
			
			// TODO ... should we validate audience, issuer, or anything else?
			var validationParameters = new TokenValidationParameters() {
				ValidateAudience = false,
				ValidateIssuer = false,
				RequireSignedTokens = true,
				IssuerSigningToken = signingToken
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
