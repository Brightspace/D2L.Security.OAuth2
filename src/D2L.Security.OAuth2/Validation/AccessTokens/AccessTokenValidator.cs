using System;
using System.Collections.Immutable;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	internal static class JsonWebTokenHandlerExtensions {

		public static TokenValidationResult ValidateToken(
			this JsonWebTokenHandler @this,
			SecurityToken token,
			TokenValidationParameters validationParameters
		) => @this.ValidateTokenAsync( token, validationParameters ).ConfigureAwait( false ).GetAwaiter().GetResult();

	}

	internal sealed partial class AccessTokenValidator : IAccessTokenValidator {
		internal static readonly ImmutableHashSet<string> ALLOWED_SIGNATURE_ALGORITHMS = ImmutableHashSet.Create(
			SecurityAlgorithms.RsaSha256,
			SecurityAlgorithms.EcdsaSha256,
			SecurityAlgorithms.EcdsaSha384,
			SecurityAlgorithms.EcdsaSha512
		);

		private readonly IPublicKeyProvider m_publicKeyProvider;
		private readonly JsonWebTokenHandler m_tokenHandler = new();

		public AccessTokenValidator(
			IPublicKeyProvider publicKeyProvider
		) {
			m_publicKeyProvider = publicKeyProvider;
		}

		[GenerateSync]
		Task IAccessTokenValidator.PrefetchAsync() => m_publicKeyProvider.PrefetchAsync();

		[GenerateSync]
		async Task<IAccessToken> IAccessTokenValidator.ValidateAsync(
			string token
		) {
			if( !m_tokenHandler.CanReadToken( token ) ) {
				throw new ValidationException( "Couldn't parse token" );
			}

			var unvalidatedToken = ( JsonWebToken )m_tokenHandler.ReadToken(
				token
			);

			if( !ALLOWED_SIGNATURE_ALGORITHMS.Contains( unvalidatedToken.Alg ) ) {
				string message = string.Format(
					"Signature algorithm '{0}' is not supported.  Permitted algorithms are '{1}'",
					unvalidatedToken.Alg,
					string.Join( ",", ALLOWED_SIGNATURE_ALGORITHMS )
				);
				throw new InvalidTokenException( message );
			}

			if( !unvalidatedToken.TryGetHeaderValue( "kid", out string keyId ) ) {
				throw new InvalidTokenException( "KeyId not found in token" );
			}

			using D2LSecurityToken signingKey = ( await m_publicKeyProvider
				.GetByIdAsync( keyId )
				.ConfigureAwait( false )
			).Ref();

			var validationParameters = new TokenValidationParameters() {
				ValidateAudience = false,
				ValidateIssuer = false,
				RequireSignedTokens = true,
				IssuerSigningKey = signingKey,
				CryptoProviderFactory = new D2LCryptoProviderFactory()
			};

			IAccessToken accessToken;

			try {
				TokenValidationResult validationResult = await m_tokenHandler.ValidateTokenAsync(
					unvalidatedToken,
					validationParameters
				).ConfigureAwait( false );
				if( !validationResult.IsValid ) {
					throw validationResult.Exception;
				}
				accessToken = new AccessToken( (JsonWebToken)validationResult.SecurityToken );
			} catch( SecurityTokenExpiredException e ) {
				throw new ExpiredTokenException( e );
			} catch( SecurityTokenNotYetValidException e ) {
				throw new ValidationException( "Token is from the future (nbf)", e );
			} catch( Exception e ) {
				throw new ValidationException( "Unknown validation exception", e );
			}

			return accessToken;
		}
	}
}
