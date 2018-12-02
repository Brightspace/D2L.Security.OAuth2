using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {

	internal partial class D2LSecurityKey : SecurityKey {

		public override string KeyId => Id.ToString();

		public override int KeySize => GetKey().KeySize;

	}
}
