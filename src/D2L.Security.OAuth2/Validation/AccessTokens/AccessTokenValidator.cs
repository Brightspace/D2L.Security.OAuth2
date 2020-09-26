﻿using System;
using System.Collections.Immutable;
using System.IdentityModel.Tokens;
using System.Threading;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Validation.Exceptions;
using D2L.Services;

#if DNXCORE50
using System.IdentityModel.Tokens.Jwt;
#endif

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	internal sealed class AccessTokenValidator : IAccessTokenValidator {
		internal static readonly ImmutableHashSet<string> ALLOWED_SIGNATURE_ALGORITHMS = ImmutableHashSet.Create(
			"RS256",
			EcDsaSecurityKey.SupportedSecurityAlgorithms.ECDsaSha256Signature,
			EcDsaSecurityKey.SupportedSecurityAlgorithms.ECDsaSha384Signature,
			EcDsaSecurityKey.SupportedSecurityAlgorithms.ECDsaSha512Signature
		);

		private readonly IPublicKeyProvider m_publicKeyProvider;
		private readonly ThreadLocal<JwtSecurityTokenHandler> m_tokenHandler = new ThreadLocal<JwtSecurityTokenHandler>(
			valueFactory: () => new JwtSecurityTokenHandler(),
			trackAllValues: false
		);

		public AccessTokenValidator(
			IPublicKeyProvider publicKeyProvider
		) {
			m_publicKeyProvider = publicKeyProvider;
		}

		async Task<IAccessToken> IAccessTokenValidator.ValidateAsync(
			string token
		) {
			var tokenHandler = m_tokenHandler.Value;

			if( !tokenHandler.CanReadToken( token ) ) {
				throw new ValidationException( "Couldn't parse token" );
			}

			var unvalidatedToken = ( JwtSecurityToken )tokenHandler.ReadToken(
				token
			);

			if( !ALLOWED_SIGNATURE_ALGORITHMS.Contains( unvalidatedToken.SignatureAlgorithm ) ) {
				string message = string.Format(
					"Signature algorithm '{0}' is not supported.  Permitted algorithms are '{1}'",
					unvalidatedToken.SignatureAlgorithm,
					string.Join( ",", ALLOWED_SIGNATURE_ALGORITHMS )
				);
				throw new InvalidTokenException( message );
			}

			if( !unvalidatedToken.Header.ContainsKey( "kid" ) ) {
				throw new InvalidTokenException( "KeyId not found in token" );
			}

			string keyId = unvalidatedToken.Header[ "kid" ].ToString();

			D2LSecurityToken signingToken = await m_publicKeyProvider
				.GetByIdAsync( keyId )
				.ConfigureAwait( false );

			var validationParameters = new TokenValidationParameters() {
				ValidateAudience = false,
				ValidateIssuer = false,
				RequireSignedTokens = true,
				IssuerSigningToken = signingToken
			};

			IAccessToken accessToken;

			try {
				tokenHandler.ValidateToken(
					token,
					validationParameters,
					out SecurityToken securityToken
				);
				accessToken = new AccessToken( ( JwtSecurityToken )securityToken );
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
