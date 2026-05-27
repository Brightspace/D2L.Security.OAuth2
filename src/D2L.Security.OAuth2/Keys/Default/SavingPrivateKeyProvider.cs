using System;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed partial class SavingPrivateKeyProvider : IPrivateKeyProvider {
		private readonly IPrivateKeyProvider m_inner;
		private readonly IPublicKeyDataProvider m_publicKeyDataProvider;

		public SavingPrivateKeyProvider(
			IPrivateKeyProvider inner,
			ISanePublicKeyDataProvider publicKeyDataProvider
		) {
			m_inner = inner;
			m_publicKeyDataProvider = publicKeyDataProvider;
		}

		[GenerateSync]
		async Task<D2LSecurityToken?> IPrivateKeyProvider.GetSigningCredentialsAsync() {
			var result = await m_inner.GetSigningCredentialsAsync().ConfigureAwait( false );


			if( result != null) {
				var jwk = result.ToJsonWebKey();
				await m_publicKeyDataProvider.SaveAsync( new Guid( jwk.Id ), jwk ).ConfigureAwait( false );
			}

			return result;
		}
	}
}
