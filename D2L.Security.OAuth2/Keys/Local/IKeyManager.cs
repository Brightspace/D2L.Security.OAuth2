using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local {
	public interface IKeyManager : IPublicKeyProvider {
		Task<string> SignAsync( UnsignedToken token );
	}
}
