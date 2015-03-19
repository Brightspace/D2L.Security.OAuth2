using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenProvisioning {
	internal class KidSecurityToken : NamedKeySecurityToken {

		public KidSecurityToken( string kid, SecurityKey key )
			: base( Constants.AssertionGrant.KEY_ID_NAME, kid, key ) { }

		public override bool CanCreateKeyIdentifierClause<T>() {
			if( typeof( T ) == typeof( NamedKeySecurityKeyIdentifierClause  ) ) {
				return true;
			}

			return base.CanCreateKeyIdentifierClause<T>();
		}

		public override T CreateKeyIdentifierClause<T>() {
			if( typeof( T ) == typeof( NamedKeySecurityKeyIdentifierClause ) ) {
				return (T)(object)new NamedKeySecurityKeyIdentifierClause(
					base.Name,
					base.Id
				);
			}

			return base.CreateKeyIdentifierClause<T>();
		}

	}
}
