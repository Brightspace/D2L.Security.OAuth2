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

		private readonly IAccessTokenProvider m_accessTokenProvider;
		private readonly ICache m_userTokenCache;
		private readonly ICache m_serviceTokenCache;
		private readonly TimeSpan m_tokenRefreshGracePeriod;
		private readonly JwtSecurityTokenHandler m_tokenHandler;

		public CachedAccessTokenProvider(
			IAccessTokenProvider accessTokenProvider,
			ICache userTokenCache,
			ICache serviceTokenCache,
			TimeSpan tokenRefreshGracePeriod
			) {
			m_accessTokenProvider = accessTokenProvider;
			m_userTokenCache = userTokenCache;
			m_serviceTokenCache = serviceTokenCache;
			m_tokenRefreshGracePeriod = tokenRefreshGracePeriod;
			
			m_tokenHandler = new JwtSecurityTokenHandler();
		}

		void IDisposable.Dispose() {
			m_accessTokenProvider.Dispose();
		}

		async Task<IAccessToken> IAccessTokenProvider.ProvisionAccessTokenAsync(
			ClaimSet claimSet,
			IEnumerable<Scope> scopes
			) {
			
			var @this = this as IAccessTokenProvider;
			return await @this.ProvisionAccessTokenAsync( claimSet.ToClaims(), scopes ).SafeAsync();
		}

		async Task<IAccessToken> IAccessTokenProvider.ProvisionAccessTokenAsync(
			IEnumerable<Claim> claims,
			IEnumerable<Scope> scopes
			) {

			claims = claims.ToList();
			scopes = scopes.ToList();

			string cacheKey = TokenCacheKeyBuilder.BuildKey( claims, scopes );

			ICache cache = GetCache( claims );

			CacheResponse cacheResponse = await cache.GetAsync( cacheKey ).SafeAsync();

			if( cacheResponse.Success ) {
				SecurityToken securityToken = m_tokenHandler.ReadToken( cacheResponse.Value );
				if( securityToken.ValidTo > DateTime.Now.Add( m_tokenRefreshGracePeriod ) ) {
					return new AccessToken( cacheResponse.Value );
				}
			}

			IAccessToken token =
				await m_accessTokenProvider.ProvisionAccessTokenAsync( claims, scopes ).SafeAsync();

			DateTime validTo = m_tokenHandler.ReadToken( token.Token ).ValidTo;

			await cache.SetAsync( cacheKey, token.Token, validTo - DateTime.Now ).SafeAsync();
			return token;
		}

		private ICache GetCache(
			IEnumerable<Claim> claims
			) {
			bool hasSubClaim = claims.Any( claim => claim.Type == Constants.Claims.USER_ID );
			return hasSubClaim ? m_userTokenCache : m_serviceTokenCache;
		}
	}
}
