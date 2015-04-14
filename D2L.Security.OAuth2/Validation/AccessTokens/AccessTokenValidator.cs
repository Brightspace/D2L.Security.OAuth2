using System;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Jwks;

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	internal sealed class AccessTokenValidator : IAccessTokenValidator {

		internal const string ALLOWED_SIGNATURE_ALGORITHM = "RS256";

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
			
			// TODO is this check necessary?
			if( unvalidatedToken.SignatureAlgorithm != ALLOWED_SIGNATURE_ALGORITHM ) {
				string message = string.Format(
					"Expected signature algorithm {0} but was {1}",
					ALLOWED_SIGNATURE_ALGORITHM,
					unvalidatedToken.SignatureAlgorithm
				);
				//throw new InvalidTokenTypeException( message );
				// If we keep this check we could recreate the above exception type
				throw new Exception( message );
			}

			if( !unvalidatedToken.Header.ContainsKey( "kid" ) ) {
				throw new Exception( "KeyId not found in token" );
			}

			string keyId = unvalidatedToken.Header["kid"].ToString();

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
				validatedToken = new ValidatedToken( (JwtSecurityToken)securityToken );

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
