using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning.Default {
	
	internal sealed class CachedAccessTokenProvider : IAccessTokenProvider {

		private readonly INonCachingAccessTokenProvider m_accessTokenProvider;
		private readonly TimeSpan m_tokenRefreshGracePeriod;
		private readonly JwtSecurityTokenHandler m_tokenHandler;

		public CachedAccessTokenProvider(
			INonCachingAccessTokenProvider accessTokenProvider,
			TimeSpan tokenRefreshGracePeriod
			) {
			m_accessTokenProvider = accessTokenProvider;
			m_tokenRefreshGracePeriod = tokenRefreshGracePeriod;
			
			m_tokenHandler = new JwtSecurityTokenHandler();
		}

		async Task<IAccessToken> IAccessTokenProvider.ProvisionAccessTokenAsync(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes,
			ICache cache
			) {
			
			var @this = this as IAccessTokenProvider;
			return await @this.ProvisionAccessTokenAsync( claimSet.ToClaims(), scopes, cache ).SafeAsync();
		}

		async Task<IAccessToken> IAccessTokenProvider.ProvisionAccessTokenAsync(
			IEnumerable<Claim> claims,
			IEnumerable<Scope> scopes,
			ICache cache
			) {

			if( cache == null ) {
				cache = new NullCache();
			}

			claims = claims.ToList();
			scopes = scopes.ToList();

			string cacheKey = TokenCacheKeyBuilder.BuildKey( claims, scopes );

			CacheResponse cacheResponse = await cache.GetAsync( cacheKey ).SafeAsync();

			if( cacheResponse.Success ) {
				SecurityToken securityToken = m_tokenHandler.ReadToken( cacheResponse.Value );
				if( securityToken.ValidTo > DateTime.UtcNow.Add( m_tokenRefreshGracePeriod ) ) {
					return new AccessToken( cacheResponse.Value );
				}
			}

			IAccessToken token =
				await m_accessTokenProvider.ProvisionAccessTokenAsync( claims, scopes ).SafeAsync();

			DateTime validTo = m_tokenHandler.ReadToken( token.Token ).ValidTo;

			await cache.SetAsync( cacheKey, token.Token, validTo - DateTime.UtcNow ).SafeAsync();
			return token;
		}
	}
}
