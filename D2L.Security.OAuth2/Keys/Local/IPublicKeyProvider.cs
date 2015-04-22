using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local {
	public interface IPublicKeyProvider {
		Task<JsonWebKey> GetByIdAsync( Guid id );
		Task<IEnumerable<JsonWebKey>> GetAllAsync();
	}
}
