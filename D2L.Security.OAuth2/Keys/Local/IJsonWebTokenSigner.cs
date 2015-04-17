using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local {
	public interface IJsonWebTokenSigner {
		Task<string> SignAsync( UnsignedToken token );
	}
}
