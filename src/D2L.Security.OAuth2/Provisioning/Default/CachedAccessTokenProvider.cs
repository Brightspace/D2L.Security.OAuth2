using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Scopes;
using D2L.CodeStyle.Annotations;

#if DNXCORE50
using System.IdentityModel.Tokens.Jwt;
#endif

namespace D2L.Security.OAuth2.Provisioning.Default {
	internal sealed partial class CachedAccessTokenProvider : IAccessTokenProvider {
		private readonly ICache m_cache;
		private readonly IAccessTokenProvider m_inner;
		private readonly Uri m_authEndpoint;
		private readonly TimeSpan m_tokenRefreshGracePeriod;
		private readonly JwtSecurityTokenHandler m_tokenHandler;

		public CachedAccessTokenProvider(
			ICache cache,
			IAccessTokenProvider inner,
			Uri authEndpoint,
			TimeSpan tokenRefreshGracePeriod
		) {
			m_cache = cache;
			m_inner = inner;
			m_authEndpoint = authEndpoint;
			m_tokenRefreshGracePeriod = tokenRefreshGracePeriod;

			m_tokenHandler = new JwtSecurityTokenHandler();
		}

		[GenerateSync]
		async Task<IAccessToken> IAccessTokenProvider.ProvisionAccessTokenAsync(
			IEnumerable<Claim> claims,
			IEnumerable<Scope> scopes
		) {
			claims = claims.ToList();
			scopes = scopes.ToList();

			string cacheKey = TokenCacheKeyBuilder.BuildKey( m_authEndpoint, claims, scopes );

			CacheResponse cacheResponse = await m_cache.GetAsync( cacheKey )
				.ConfigureAwait( false );

			if( cacheResponse.Success ) {
				SecurityToken securityToken = m_tokenHandler.ReadToken( cacheResponse.Value );
				if( securityToken.ValidTo > DateTime.UtcNow.Add( m_tokenRefreshGracePeriod ) ) {
					return new AccessToken( cacheResponse.Value );
				}
			}

			IAccessToken token = await m_inner.ProvisionAccessTokenAsync(
				claims,
				scopes
			).ConfigureAwait( false );

			DateTime validTo = m_tokenHandler.ReadToken( token.Token ).ValidTo;

			await m_cache.SetAsync(
				cacheKey,
				token.Token,
				expiry: validTo - DateTime.UtcNow
			).ConfigureAwait( false );

			return token;
		}
	}
}
