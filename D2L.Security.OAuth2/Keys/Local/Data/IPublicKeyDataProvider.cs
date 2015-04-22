using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local.Data {
	public interface IPublicKeyDataProvider {
		Task<JsonWebKey> GetByIdAsync( Guid id );
		Task<IEnumerable<JsonWebKey>> GetAllAsync();
		Task SaveAsync( JsonWebKey key );
		Task DeleteAsync( Guid id );
	}
}