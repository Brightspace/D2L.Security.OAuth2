using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Default {

	internal sealed class SavingPrivateKeyProvider : IPrivateKeyProvider {

		private readonly IPrivateKeyProvider m_inner;
		private readonly IPublicKeyDataProvider m_publicKeyDataProvider;

		public SavingPrivateKeyProvider(
			IPrivateKeyProvider inner,
			ISanePublicKeyDataProvider publicKeyDataProvider
		) {
			m_inner = inner;
			m_publicKeyDataProvider = publicKeyDataProvider;
		}

		async Task<D2LSecurityToken> IPrivateKeyProvider.GetSigningCredentialsAsync() {
			D2LSecurityToken result = await m_inner.GetSigningCredentialsAsync().SafeAsync();

			JsonWebKey jwk = result.ToJsonWebKey();

			await m_publicKeyDataProvider.SaveAsync( jwk ).SafeAsync();

			return result;
		}
	}
}
