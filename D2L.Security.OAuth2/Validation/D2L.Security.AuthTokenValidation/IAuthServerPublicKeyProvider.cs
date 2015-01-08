using System.Security.Cryptography;

namespace D2L.Security.AuthTokenValidation {

	internal interface IAuthServerPublicKeyProvider {
		CngKey Get();
	}
}
