using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.AuthTokenProvisioning.Default;
using D2L.Security.AuthTokenProvisioning.Invocation;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenProvisioning.Tests.Unit.Default {
	
	[TestFixture]
	internal sealed partial class AuthTokenProviderTests {

		[Test]
		public async void ProvisionAccessTokenAsync_AssertionTokenIsSigned() {
			byte[] privateKey;
			byte[] publicKey;
			MakeKeyPair( out privateKey, out publicKey );

			InvocationParameters actualInvocationParams = null;
			Mock<IAuthServiceInvoker> invokerMock = new Mock<IAuthServiceInvoker>();
			invokerMock
				.Setup( x => x.ProvisionAccessTokenAsync( It.IsAny<InvocationParameters>() ) )
				.Callback<InvocationParameters>( x => actualInvocationParams = x )
				.Returns( () => Task.FromResult<string>( ASSERTION_GRANT_RESPONSE ) );
			IAuthTokenProvider provider = new AuthTokenProvider( invokerMock.Object );

			ProvisioningParameters provisioningParams;
			using( RSACryptoServiceProvider rsaService = MakeCryptoServiceProvider() ) {
				rsaService.ImportCspBlob( privateKey );

				provisioningParams = PROVISIONING_PARAMS( rsaService );
				await provider.ProvisionAccessTokenAsync( provisioningParams );
			}

			string signedToken = actualInvocationParams.Assertion;

			JwtSecurityToken signatureCheckedToken = CheckSignatureAndGetToken( signedToken, publicKey );
			Assert.AreEqual( provisioningParams.UserId, signatureCheckedToken.Subject );
		}
	}
}
