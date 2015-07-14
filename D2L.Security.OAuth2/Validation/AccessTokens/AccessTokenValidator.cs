using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	internal sealed class AccessTokenValidator : IAccessTokenValidator {

		internal static string[] ALLOWED_SIGNATURE_ALGORITHMS = new string[] {
			"RS256",
			EcDsaSecurityKey.SupportedSecurityAlgorithms.ECDsaSha256Signature,
			EcDsaSecurityKey.SupportedSecurityAlgorithms.ECDsaSha384Signature,
			EcDsaSecurityKey.SupportedSecurityAlgorithms.ECDsaSha512Signature
		};

		private readonly IPublicKeyProvider m_publicKeyProvider;
		private readonly JwtSecurityTokenHandler m_tokenHandler = new JwtSecurityTokenHandler();

		public AccessTokenValidator(
			IPublicKeyProvider publicKeyProvider
		) {
			m_publicKeyProvider = publicKeyProvider;
		}

		async Task<IValidationResponse> IAccessTokenValidator.ValidateAsync(
			string token
		) {
			
			var unvalidatedToken = (JwtSecurityToken)m_tokenHandler.ReadToken(
				token
			);
			
			if( !ALLOWED_SIGNATURE_ALGORITHMS.Contains( unvalidatedToken.SignatureAlgorithm ) ) {
				string message = string.Format(
					"Signature algorithm '{0}' is not supported.  Permitted algorithms are '{1}'",
					unvalidatedToken.SignatureAlgorithm,
					ALLOWED_SIGNATURE_ALGORITHMS
				);
				throw new InvalidSignatureAlgorithmException( message );
			}

			if( !unvalidatedToken.Header.ContainsKey( "kid" ) ) {
				throw new MissingKeyIdException( "KeyId not found in token" );
			}

			string keyId = unvalidatedToken.Header["kid"].ToString();
			Guid id;
			if( !Guid.TryParse( keyId, out id ) ) {
				throw new Exception( "ffooof TODO" );
			}

			D2LSecurityToken signingToken = await m_publicKeyProvider
				.GetByIdAsync( id )
				.SafeAsync();

			var validationParameters = new TokenValidationParameters() {
				ValidateAudience = false,
				ValidateIssuer = false,
				RequireSignedTokens = true,
				IssuerSigningToken = signingToken
			};

			IAccessToken accessToken;
			try {

				SecurityToken securityToken;
				m_tokenHandler.ValidateToken(
					token,
					validationParameters,
					out securityToken
					);
				accessToken = new AccessToken( (JwtSecurityToken) securityToken );

			} catch( SecurityTokenExpiredException ) {

				return new ValidationResponse(
					ValidationStatus.Expired,
					accessToken: null );
			}

			return new ValidationResponse(
				ValidationStatus.Success,
				accessToken
			);
		}
	}
}
