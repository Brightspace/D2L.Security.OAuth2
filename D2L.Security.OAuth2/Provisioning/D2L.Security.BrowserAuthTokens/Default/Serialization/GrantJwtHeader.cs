using System.Runtime.Serialization;

namespace D2L.Security.BrowserAuthTokens.Default.Serialization {

	[DataContract]
	internal sealed class GrantJwtHeader {
		[DataMember]
		public string typ {
			get { return "JWT"; }
			private set { }
		}

		[DataMember]
		public string alg { 
			get { return "RS256"; }
			private set { }
		}
	}
}
