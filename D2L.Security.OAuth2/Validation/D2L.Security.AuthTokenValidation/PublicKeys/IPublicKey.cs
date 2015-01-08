using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	
	/// <summary>
	/// Used to decrypt a JWT
	/// </summary>
	interface IPublicKey {
		string Contents { get; }
	}
}
