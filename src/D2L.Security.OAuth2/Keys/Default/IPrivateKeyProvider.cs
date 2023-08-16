using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Keys.Default {
	internal partial interface IPrivateKeyProvider {
		[GenerateSync]
		Task<D2LSecurityToken> GetSigningCredentialsAsync();
	}
}
