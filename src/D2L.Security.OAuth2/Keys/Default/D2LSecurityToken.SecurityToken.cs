using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using D2L.Security.OAuth2.Provisioning;

namespace D2L.Security.OAuth2.Keys.Default {

	partial class D2LSecurityToken : SecurityToken {

		public override string Id { get { return KeyId.ToString(); } }

		public override string Issuer {
			get { return null; }
		}

		public override SecurityKey SecurityKey {
			get { return GetKey(); }
		}

		public override SecurityKey SigningKey {
			get { return GetKey(); }
			set { }
		}

	}
}
