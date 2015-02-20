using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenProvisioning.Default;
using D2L.Security.AuthTokenProvisioning.Invocation;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenProvisioning.Tests.Unit.Default {
	
	[TestFixture]
	internal sealed class AuthTokenProviderTests {

		[Test]
		public void a() {
			InvocationParameters actualInvocationParams = null;
			Mock<IAuthServiceInvoker> invokerMock = new Mock<IAuthServiceInvoker>();
			invokerMock
				.Setup( x => x.ProvisionAccessToken( It.IsAny<InvocationParameters>() ) )
				.Callback<InvocationParameters>( x => actualInvocationParams = x )
				.Returns( "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSIsImtpZCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSJ9.eyJjbGllbnRfaWQiOiJsbXMuZGV2LmQybCIsInNjb3BlIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMubWFuYWdlIiwic3ViIjoic29tZVZhbGlkVXNlciIsImFtciI6Imp3dC1iZWFyZXIiLCJhdXRoX3RpbWUiOiIxNDI0NDQ4OTIxIiwiaWRwIjoiaWRzcnYiLCJ0ZW5hbnRpZCI6InNvbWVWYWxpZFRlbmFudElkIiwidGVuYW50dXJsIjoic29tZVZhbGlkVGVuYW50VXJsIiwieHQiOiJzb21lVmFsaWRYc3JmIiwiaXNzIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgiLCJhdWQiOiJodHRwczovL2FwaS5icmlnaHRzcGFjZS5jb20vYXV0aC9yZXNvdXJjZXMiLCJleHAiOjE0MjQ0NTI1MjEsIm5iZiI6MTQyNDQ0ODkyMX0.FEy7aLi8tuaAxYze0Uu2jn5Kft25TL_h_FZi_AzOzga-S4-1ZjnVk3DxRyY2-MrPR7aSG4khQ2FbHHfFW6HIQiwEk5d6uLWND5FPP6Q3OxUS-0iTwEitFYzwQH-xBFOSFQvakuFRRXd1xDehOlth6y4lQYpwJDAZ4hpCgw7oZovXjSFUpEfHCyS66R_Hd2vquMDRI1RxoYRNkRCDFygNt7f-JXPUksjMmpRQX_YnMGbPPLyAQbdeAujO_IX3DuWMJfsk46aPlgilx6FXPPWVgpHEr-9uwJDWRbhT-LogY8amgA3-x1fdbDtsyjlaxWsL5VuDXd9gmBbW3ib6_DhB7A\",\"expires_in\":3600,\"token_type\":\"Bearer\"}" );

			byte[] privateAndPublicKeyPairBlob;
			byte[] publicKeyBlob;

			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider( 2048 ) ) {
				rsaService.PersistKeyInCsp = false;

				privateAndPublicKeyPairBlob = rsaService.ExportCspBlob( true );
				publicKeyBlob = rsaService.ExportCspBlob( false );

				RsaSecurityKey rsaSecurityKey = new RsaSecurityKey( rsaService );
				SigningCredentials signingCredentials =
					new SigningCredentials( rsaSecurityKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );

				IAuthTokenProvider provider = new AuthTokenProvider(
					signingCredentials,
					invokerMock.Object
					);



				string clientId = "lms.dev.d2l";
				string clientSecret = "lms_secret";
				IEnumerable<string> scopes = new string[] { "https://api.brightspace.com/auth/lores.manage" };
				string tenantId = "mytenantid";
				string tenantUrl = "mytenanturl";
				ProvisioningParameters provisioningParams = new ProvisioningParameters(
					clientId,
					clientSecret,
					scopes,
					tenantId,
					tenantUrl
					);

				provider.ProvisionAccessToken( provisioningParams );
			}

			// invalidate public key to test negative case!
			//publicKeyBlob[103] = 55;

			// now check signature using public key
			string serializedAssertionToken = actualInvocationParams.Assertion;
			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider( 2048 ) ) {
				rsaService.PersistKeyInCsp = false;
				rsaService.ImportCspBlob( publicKeyBlob );
				
				RsaSecurityToken rsaScurityToken = new RsaSecurityToken( rsaService );
				SecurityKey securityKey = rsaScurityToken.SecurityKeys[0];

				TokenValidationParameters validationParameters = CreateTokenValidationParameters( securityKey );

				ISecurityTokenValidator tokenHandler = CreateTokenHandler();

				SecurityToken securityToken;
				ClaimsPrincipal principal = tokenHandler.ValidateToken( serializedAssertionToken, validationParameters, out securityToken );

				JwtSecurityToken jwtSecurityToken = (JwtSecurityToken)securityToken;
			}
		}

		private static void Assert( InvocationParameters invocationParams ) {
			
		}

		private static ISecurityTokenValidator CreateTokenHandler() {
			SecurityTokenHandlerConfiguration tokenHandlerConfiguration =
				new SecurityTokenHandlerConfiguration();
			tokenHandlerConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;
			tokenHandlerConfiguration.CertificateValidator = X509CertificateValidator.None;

			JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
			tokenHandler.Configuration = tokenHandlerConfiguration;

			return tokenHandler;
		}

		private static TokenValidationParameters CreateTokenValidationParameters( SecurityKey securityKey ) {
			TokenValidationParameters validationParameters = new TokenValidationParameters();
			validationParameters.IssuerSigningKey = securityKey;
			validationParameters.ValidateIssuerSigningKey = true;
			validationParameters.ValidateLifetime = false;
			validationParameters.ValidateIssuer = false;
			validationParameters.ValidateAudience = false;
			validationParameters.ValidateActor = false;
			
			return validationParameters;
		}
	}
}
