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

			await SignTokenAsync( invokerMock.Object, privateKey );
			string signedToken = actualInvocationParams.Assertion;

			JwtSecurityToken signatureCheckedToken = CheckSignatureAndGetToken( signedToken, publicKey );
			Assert.AreEqual( PROVISIONING_PARAMS.UserId, signatureCheckedToken.Subject );
		}

		private async static Task SignTokenAsync( IAuthServiceInvoker serviceInvoker, byte[] signingKey ) {

			using( RSACryptoServiceProvider rsaService = MakeCryptoServiceProvider() ) {
				rsaService.ImportCspBlob( signingKey );

				RsaSecurityKey rsaSecurityKey = new RsaSecurityKey( rsaService );
				SigningCredentials signingCredentials = new SigningCredentials(
					rsaSecurityKey,
					SecurityAlgorithms.RsaSha256Signature,
					SecurityAlgorithms.Sha256Digest
					);

				IAuthTokenProvider provider = new AuthTokenProvider(
					signingCredentials,
					serviceInvoker
					);

				await provider.ProvisionAccessTokenAsync( PROVISIONING_PARAMS );
			}
		}
	}
}
