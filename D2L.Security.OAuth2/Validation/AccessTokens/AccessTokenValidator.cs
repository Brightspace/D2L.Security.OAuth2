using System;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using D2L.Security.OAuth2.SecurityTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
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
			
			if( unvalidatedToken.SignatureAlgorithm != ALLOWED_SIGNATURE_ALGORITHM ) {
				string message = string.Format(
					"Signature algorithm '{0}' is not supported.  Permitted algorithm is '{1}'",
					unvalidatedToken.SignatureAlgorithm,
					ALLOWED_SIGNATURE_ALGORITHM
				);
				throw new InvalidSignatureAlgorithmException( message );
			}

			if( !unvalidatedToken.Header.ContainsKey( "kid" ) ) {
				throw new MissingKeyIdException( "KeyId not found in token" );
			}

			string keyId = unvalidatedToken.Header["kid"].ToString();
			IValidatedToken validatedToken = null;

			using( D2LSecurityToken signingToken = await m_publicKeyProvider.GetSecurityTokenAsync(
				jwksEndPoint: jwksEndPoint,
				keyId: keyId
			).SafeAsync() ) {

				var validationParameters = new TokenValidationParameters() {
					ValidateAudience = false,
					ValidateIssuer = false,
					RequireSignedTokens = true,
					IssuerSigningToken = signingToken
				};
				
				try {

					SecurityToken securityToken;
					m_tokenHandler.ValidateToken(
						token,
						validationParameters,
						out securityToken
						);
					validatedToken = new ValidatedToken( (JwtSecurityToken) securityToken );

				} catch( SecurityTokenExpiredException ) {

					return new ValidationResponse(
						ValidationStatus.Expired,
						token: null
						);
				}
			}

			return new ValidationResponse(
				ValidationStatus.Success,
				validatedToken
			);

		}
	}
}
