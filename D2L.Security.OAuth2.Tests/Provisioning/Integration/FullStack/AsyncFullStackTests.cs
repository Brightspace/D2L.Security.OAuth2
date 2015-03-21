using System;
using System.IdentityModel.Tokens;
using System.Net;
using D2L.Security.OAuth2.Provisioning.Tests.Utilities;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Provisioning.Tests.Integration.FullStack {

	[Ignore( "Needs a new strategy of becoming trusted by the auth service" )]
	[TestFixture]
	internal sealed class AsyncFullStackTests {

		//private const string USER_ID = "someValidUser";
		//private const string TENANT_ID = "someValidTenantId";
		//private const string TENANT_URL = "someValidTenantUrl";
		//private const string XSRF = "someValidXsrf";

		//private readonly IAuthTokenProvider m_tokenProvider = 
		//	AuthTokenProviderFactory.Create(
		//		TestCredentials.LMS.CERTIFICATE,
		//		TestUris.AUTH_TOKEN_PROVISIONING_URI
		//		);

		//[Test]
		//public async void IAuthTokenProvider_ProvisionAccessTokenAsync_Success() {
		//	ProvisioningParameters provisioningParams =
		//		TestParameters.MakeValidProvisioningParams( USER_ID, TENANT_ID, TENANT_URL, XSRF );
		//	IAccessToken serializedAccessToken = await m_tokenProvider.ProvisionAccessTokenAsync( provisioningParams );

		//	JwtSecurityToken token = new JwtSecurityToken( serializedAccessToken.Token );

		//	token.AssertHasClaim( Constants.Claims.XSRF, XSRF );
		//	token.AssertHasClaim( Constants.Claims.USER, USER_ID );
		//	token.AssertHasClaim( Constants.Claims.TENANT_URL, TENANT_URL );
		//	token.AssertHasClaim( Constants.Claims.TENANT_ID, TENANT_ID );
		//}

		//[Test]
		//public async void IAuthTokenProvider_ProvisionAccessTokenAsync_NoUserId_Success() {
		//	ProvisioningParameters provisioningParams =
		//		TestParameters.MakeValidProvisioningParams( null, TENANT_ID, TENANT_URL, XSRF );
		//	IAccessToken serializedAccessToken = await m_tokenProvider.ProvisionAccessTokenAsync( provisioningParams );

		//	JwtSecurityToken token = new JwtSecurityToken( serializedAccessToken.Token );

		//	token.AssertDoesNotHaveClaim( Constants.Claims.USER );
		//	token.AssertHasClaim( Constants.Claims.XSRF, XSRF );
		//	token.AssertHasClaim( Constants.Claims.TENANT_URL, TENANT_URL );
		//	token.AssertHasClaim( Constants.Claims.TENANT_ID, TENANT_ID );
		//}

		//[Test]
		//public async void IAuthTokenProvider_ProvisionAccessTokenAsync_NoXsrf_Success() {
		//	ProvisioningParameters provisioningParams =
		//		TestParameters.MakeValidProvisioningParams( USER_ID, TENANT_ID, TENANT_URL, null );
		//	IAccessToken serializedAccessToken = await m_tokenProvider.ProvisionAccessTokenAsync( provisioningParams );

		//	JwtSecurityToken token = new JwtSecurityToken( serializedAccessToken.Token );

		//	token.AssertDoesNotHaveClaim( Constants.Claims.XSRF );
		//	token.AssertHasClaim( Constants.Claims.USER, USER_ID );
		//	token.AssertHasClaim( Constants.Claims.TENANT_URL, TENANT_URL );
		//	token.AssertHasClaim( Constants.Claims.TENANT_ID, TENANT_ID );
		//}

		//[Test]
		//public void IAuthTokenProvider_ProvisionAccessTokenAsync_InvalidServerUri_Throws() {
		//	IAuthTokenProvider tokenProvider = AuthTokenProviderFactory.Create(
		//		TestCredentials.LMS.CERTIFICATE,
		//		new Uri( "http://somebogusserver.d2l" )
		//		);
		//	ProvisioningParameters provisioningParams = TestParameters.MakeValidProvisioningParams();
		//	Assert.Throws<WebException>( async () => await tokenProvider.ProvisionAccessTokenAsync( provisioningParams ) );
		//}
	}
}
