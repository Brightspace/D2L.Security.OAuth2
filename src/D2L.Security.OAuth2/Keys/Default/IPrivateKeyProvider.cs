using System.Threading.Tasks;
using static D2L.CodeStyle.Annotations.Objects;

namespace D2L.Security.OAuth2.Keys.Default {

	[Immutable]
	internal interface IPrivateKeyProvider {
		Task<D2LSecurityToken> GetSigningCredentialsAsync();
	}
}
